package gearth.app.services.unity_tools;

import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptInitializer;
import com.github.monkeywie.proxyee.intercept.HttpProxyInterceptPipeline;
import com.github.monkeywie.proxyee.intercept.common.FullRequestIntercept;
import com.github.monkeywie.proxyee.intercept.common.FullResponseIntercept;
import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.List;

public class GUnityFileServer extends HttpProxyInterceptInitializer
{
    private static final Logger LOG = LoggerFactory.getLogger(GUnityFileServer.class);

    /**
     * Default max content length size is 100MB
     */
    private static final int DEFAULT_MAX_CONTENT_LENGTH = 1024 * 1024 * 100;

    private static final String HABBO_HOST = "images.habbo.com";
    private static final List<String> HABBO_ASSETS = List.of(
            ".*/WebGL/habbo2020-global-prod/StreamingAssets/Version.txt",
            ".*/WebGL/habbo2020-global-prod/Build/habbo2020-global-prod.data.gz",
            ".*/WebGL/habbo2020-global-prod/Build/habbo2020-global-prod.wasm.gz",
            ".*/WebGL/habbo2020-global-prod/Build/habbo2020-global-prod.framework.js.gz",
            ".*/WebGL/habbo2020-global-prod/Build/habbo2020-global-prod.loader.js"
    );

    private static final UnityWebModifier modifier = new UnityWebModifier();

    private static final String HeaderAge = "Age";
    private static final String HeaderCacheControl = "Cache-Control";
    private static final String HeaderETag = "ETag";
    private static final String HeaderIfNoneMatch = "If-None-Match";
    private static final String HeaderIfModifiedSince = "If-Modified-Since";
    private static final String HeaderLastModified = "Last-Modified";
    private static final String HeaderDate = "Date";
    private static final String HeaderExpires = "Expires";

    private final int websocketPort;

    public GUnityFileServer(final int websocketPort) {
        this.websocketPort = websocketPort;
    }

    @Override
    public void init(HttpProxyInterceptPipeline pipeline) {
        pipeline.addLast(new FullRequestIntercept(DEFAULT_MAX_CONTENT_LENGTH) {
            @Override
            public boolean match(HttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
                return isTargetAsset(pipeline.getRequestProto().getHost(), httpRequest.uri());
            }

            @Override
            public void handleRequest(FullHttpRequest httpRequest, HttpProxyInterceptPipeline pipeline) {
                stripCacheHeaders(httpRequest.headers());
            }
        });

        pipeline.addLast(new FullResponseIntercept(DEFAULT_MAX_CONTENT_LENGTH) {
            @Override
            public boolean match(HttpRequest httpRequest, HttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                if (httpResponse.status().code() != 200) {
                    return false;
                }

                return isTargetAsset(pipeline.getRequestProto().getHost(), httpRequest.uri());
            }

            @Override
            public void handleResponse(HttpRequest httpRequest, FullHttpResponse httpResponse, HttpProxyInterceptPipeline pipeline) {
                LOG.info("Intercepted response for {}", httpRequest.uri());

                stripCacheHeaders(httpResponse.headers());

                httpResponse.headers().add("X-Modified-By", "G-Earth");

                final String revision = extractRevision(httpRequest.uri());

                try {
                    if (httpRequest.uri().endsWith("/StreamingAssets/Version.txt")) {
                        LOG.info("Modifying version");

                        responseWrite(httpResponse, responseRead(httpResponse) + " - G-Earth");
                    } else if (httpRequest.uri().endsWith("/Build/habbo2020-global-prod.wasm.gz")) {
                        LOG.info("Modifying wasm code");

                        final byte[] content = responseReadBytes(httpResponse);

                        responseWriteBytes(httpResponse, modifier.modifyCodeFile(revision, content));
                    } else if (httpRequest.uri().endsWith("/Build/habbo2020-global-prod.framework.js.gz")) {
                        LOG.info("Modifying framework");

                        final String content = responseRead(httpResponse);

                        responseWrite(httpResponse, modifier.modifyFrameworkFile(revision, websocketPort, content));
                    } else if (httpRequest.uri().endsWith("/Build/habbo2020-global-prod.loader.js")) {
                        LOG.info("Modifying loader");

                        final String content = responseRead(httpResponse);

                        responseWrite(httpResponse, modifier.modifyLoaderFile(content));
                    }
                } catch (UnityWebModifierException e) {
                    LOG.error("Failed to modify framework file", e);

                    httpResponse.setStatus(HttpResponseStatus.INTERNAL_SERVER_ERROR);
                }
            }
        });
    }

    private static String extractRevision(final String uri) {
        final int webgl = uri.indexOf("/WebGL/");
        if (webgl <= 0) {
            return "unknown";
        }
        final String prefix = uri.substring(0, webgl);
        return prefix.substring(prefix.lastIndexOf('/') + 1);
    }

    private static boolean isTargetAsset(final String host, final String uri) {
        if (!HABBO_HOST.equals(host)) {
            return false;
        }

        for (final String asset : HABBO_ASSETS) {
            if (uri.matches(asset)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Strip cache headers from the response.
     */
    private static void stripCacheHeaders(HttpHeaders headers) {
        headers.remove(HeaderAge);
        headers.remove(HeaderCacheControl);
        headers.remove(HeaderETag);
        headers.remove(HeaderIfNoneMatch);
        headers.remove(HeaderIfModifiedSince);
        headers.remove(HeaderLastModified);
        headers.remove(HeaderDate);
        headers.remove(HeaderExpires);
    }

    private static String responseRead(FullHttpResponse response) {
        final ByteBuf contentBuf = response.content();
        return contentBuf.toString(StandardCharsets.UTF_8);
    }

    private static byte[] responseReadBytes(FullHttpResponse response) {
        final ByteBuf contentBuf = response.content();
        final byte[] bytes = new byte[contentBuf.readableBytes()];
        contentBuf.readBytes(bytes);
        return bytes;
    }

    private static void responseWrite(FullHttpResponse response, String content) {
        responseWriteBytes(response, content.getBytes(StandardCharsets.UTF_8));
    }

    private static void responseWriteBytes(FullHttpResponse response, byte[] content) {
        // Update content.
        response.content().clear().writeBytes(content);

        // Update content-length.
        HttpUtil.setContentLength(response, content.length);

        // Ensure modified response is not cached.
        stripCacheHeaders(response.headers());
    }
}

