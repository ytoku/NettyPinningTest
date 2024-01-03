package com.example.nettypinningtest

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.example.nettypinningtest.ui.theme.NettyPinningTestTheme
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.FingerprintTrustManagerFactory
import io.netty.resolver.dns.DnsAddressResolverGroup
import io.netty.resolver.dns.DnsNameResolverBuilder
import io.netty.resolver.dns.SingletonDnsServerAddressStreamProvider
import reactor.netty.http.Http11SslContextSpec
import reactor.netty.http.client.HttpClient
import reactor.netty.tcp.SslProvider
import reactor.netty.tcp.SslProvider.SslContextSpec
import java.net.InetAddress
import java.net.InetSocketAddress


class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Thread.sleep(1000)
        setContent {
            NettyPinningTestTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val result = AccessToExampleCom();
                    if (result != null) {
                        SetText(text = result)
                    }
                }
            }
        }
    }
}

@Composable
fun AccessToExampleCom(): String? {
    val trustManager = FingerprintTrustManagerFactory
        .builder("SHA-256")
        .fingerprints(
            "5E:F2:F2:14:26:0A:B8:F5:8E:55:EE:A4:2E:4A:C0:4B:0F:17:18:07:D8:D1:18:5F:DD:D6:74:70:E9:AB:60:96",
            // "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
            )
        .build()
    val sslContext = SslContextBuilder.forClient()
        .trustManager(trustManager)
        .build()

    val client = HttpClient.create()
        .secure { spec: SslProvider.SslContextSpec ->
            spec.sslContext(sslContext).build()
        }

    val dnsServerAddress = InetSocketAddress(
        InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)),
        53
    )

    return try {
        val resp = client
            .resolver { spec ->
                spec.dnsAddressResolverGroupProvider { builder ->
                    DnsAddressResolverGroup(
                        builder.nameServerProvider(
                            SingletonDnsServerAddressStreamProvider(dnsServerAddress)
                        )
                    )
                }
            }
            .get()
            .uri("https://example.com/")
            .response()
            .block()
        resp?.status().toString()
    } catch (e: Exception) {
        e.toString()
    }
}

@Composable
fun SetText(text: String) {
    Text(
        text = text,
        modifier = Modifier
    )
}
