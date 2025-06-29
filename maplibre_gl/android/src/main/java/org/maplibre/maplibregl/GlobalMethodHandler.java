package org.maplibre.maplibregl;

import android.content.Context;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import org.maplibre.android.net.ConnectivityReceiver;
import io.flutter.embedding.engine.plugins.FlutterPlugin;
import io.flutter.plugin.common.BinaryMessenger;
import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

class GlobalMethodHandler implements MethodChannel.MethodCallHandler {
  private static final String TAG = GlobalMethodHandler.class.getSimpleName();
  private static final String DATABASE_NAME = "mbgl-offline.db";
  private static final int BUFFER_SIZE = 1024 * 2;
  @NonNull private final Context context;
  @NonNull private final BinaryMessenger messenger;
  @Nullable private FlutterPlugin.FlutterAssets flutterAssets;
  @Nullable private OfflineChannelHandlerImpl downloadOfflineRegionChannelHandler;


  GlobalMethodHandler(@NonNull FlutterPlugin.FlutterPluginBinding binding) {
    this.context = binding.getApplicationContext();
    this.flutterAssets = binding.getFlutterAssets();
    this.messenger = binding.getBinaryMessenger();
  }

  private static void copy(InputStream input, OutputStream output) throws IOException {
    final byte[] buffer = new byte[BUFFER_SIZE];
    final BufferedInputStream in = new BufferedInputStream(input, BUFFER_SIZE);
    final BufferedOutputStream out = new BufferedOutputStream(output, BUFFER_SIZE);
    int count = 0;
    int n = 0;
    try {
      while ((n = in.read(buffer, 0, BUFFER_SIZE)) != -1) {
        out.write(buffer, 0, n);
        count += n;
      }
      out.flush();
    } finally {
      try {
        out.close();
      } catch (IOException e) {
        Log.e(TAG, e.getMessage(), e);
      }
      try {
        in.close();
      } catch (IOException e) {
        Log.e(TAG, e.getMessage(), e);
      }
    }
  }

  @Override
  public void onMethodCall(MethodCall methodCall, MethodChannel.Result result) {
    MapLibreUtils.getMapLibre(context);

    switch (methodCall.method) {
      case "installOfflineMapTiles":
        String tilesDb = methodCall.argument("tilesdb");
        installOfflineMapTiles(tilesDb);
        result.success(null);
        break;
      case "setOffline":
        boolean offline = methodCall.argument("offline");
        ConnectivityReceiver.instance(context).setConnected(offline ? false : null);
        result.success(null);
        break;
      case "mergeOfflineRegions":
        OfflineManagerUtils.mergeRegions(result, context, methodCall.argument("path"));
        break;
      case "setOfflineTileCountLimit":
        OfflineManagerUtils.setOfflineTileCountLimit(
            result, context, methodCall.<Number>argument("limit").longValue());
        break;
      case "setHttpHeaders":
        Map<String, String> headers = (Map<String, String>) methodCall.argument("headers");
        MapLibreHttpRequestUtil.setHttpHeaders(headers, result);
        break;
      case "setSslCertificateBypass":
        boolean enabled = methodCall.argument("enabled");
        MapLibreHttpRequestUtil.setSslCertificateBypass(enabled, result);
        break;
      case "downloadOfflineRegion#setup":
        String channelName = methodCall.argument("channelName");
        // Prepare args
        downloadOfflineRegionChannelHandler = new OfflineChannelHandlerImpl(messenger, channelName);
        result.success(null);
        break;
      case "downloadOfflineRegion":
        // Get args from caller
        Map<String, Object> definitionMap = (Map<String, Object>) methodCall.argument("definition");
        Map<String, Object> metadataMap = (Map<String, Object>) methodCall.argument("metadata");

        if (downloadOfflineRegionChannelHandler == null) {
          result.error(
                  "downloadOfflineRegion#setup NOT CALLED",
                  "The setup has not been called, please call downloadOfflineRegion#setup before",
                  null);
          break;
        }

        // Start downloading
        OfflineManagerUtils.downloadRegion(
            result, context, definitionMap, metadataMap, downloadOfflineRegionChannelHandler);
        downloadOfflineRegionChannelHandler = null;
        break;
      case "getListOfRegions":
        OfflineManagerUtils.regionsList(result, context);
        break;
      case "updateOfflineRegionMetadata":
        // Get download region arguments from caller
        Map<String, Object> metadata = (Map<String, Object>) methodCall.argument("metadata");
        OfflineManagerUtils.updateRegionMetadata(
            result, context, methodCall.<Number>argument("id").longValue(), metadata);
        break;
      case "deleteOfflineRegion":
        OfflineManagerUtils.deleteRegion(
            result, context, methodCall.<Number>argument("id").longValue());
        break;
      default:
        result.notImplemented();
        break;
    }
  }

  private void installOfflineMapTiles(String tilesDb) {
    final File dest = new File(context.getFilesDir(), DATABASE_NAME);
    try (InputStream input = openTilesDbFile(tilesDb);
        OutputStream output = new FileOutputStream(dest)) {
      copy(input, output);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private InputStream openTilesDbFile(String tilesDb) throws IOException {
    if (tilesDb.startsWith("/")) { // Absolute path.
      return new FileInputStream(new File(tilesDb));
    } else {
      String assetKey;
      if (flutterAssets != null) {
        assetKey = flutterAssets.getAssetFilePathByName(tilesDb);
      } else {
        throw new IllegalStateException();
      }
      return context.getAssets().open(assetKey);
    }
  }
}
