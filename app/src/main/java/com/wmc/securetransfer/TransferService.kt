package com.wmc.securetransfer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/** Started from a visible user action; never restarted automatically after process death. */
class TransferService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val transfers get() = (application as TransferApplication).transfers
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    override fun onCreate() {
        super.onCreate()
        try {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL, "Secure file transfers", NotificationManager.IMPORTANCE_LOW),
            )
            ServiceCompat.startForeground(this, NOTIFICATION, notification(transfers.state.value),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            wakeLock = getSystemService(PowerManager::class.java).newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK, "SecureTransfer:active",
            ).apply { acquire(6L * 60 * 60 * 1000) }
            @Suppress("DEPRECATION")
            wifiLock = (applicationContext.getSystemService(WIFI_SERVICE) as WifiManager).createWifiLock(
                WifiManager.WIFI_MODE_FULL_HIGH_PERF, "SecureTransfer:network",
            ).apply { acquire() }
            scope.launch {
                transfers.state.collect { state ->
                    if (!state.busy && !state.receiving) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    } else getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification(state))
                }
            }
        } catch (error: RuntimeException) {
            transfers.cancelAll("Android could not start background execution: ${error.message}. Keep the app visible and retry.")
            stopSelf()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CANCEL) transfers.cancelAll()
        return START_NOT_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        transfers.cancelAll("Android ended the background-transfer time allowance. Open the app to retry.")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        transfers.cancelAll("Transfer service stopped")
        scope.cancel()
        wifiLock?.let { if (it.isHeld) it.release() }
        wakeLock?.let { if (it.isHeld) it.release() }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(state: UiState): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val cancel = PendingIntent.getService(this, 1, Intent(this, TransferService::class.java).setAction(ACTION_CANCEL),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(if (state.verificationPending) "Compare codes on both phones" else "Secure Adaptive Transfer")
            .setContentText(state.progressLabel.take(180))
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setProgress(1000, state.progress, state.progressIndeterminate)
            .addAction(0, "Cancel", cancel).build()
    }

    companion object {
        private const val CHANNEL = "secure_transfers"
        private const val NOTIFICATION = 8988
        const val ACTION_CANCEL = "com.wmc.securetransfer.CANCEL_TRANSFER"
    }
}
