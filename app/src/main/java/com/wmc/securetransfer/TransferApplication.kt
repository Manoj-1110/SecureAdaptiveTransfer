package com.wmc.securetransfer

import android.app.Application

/** Application/service ownership keeps sockets and prompts alive when an Activity is recreated. */
class TransferApplication : Application() {
    val transfers: TransferCoordinator by lazy { TransferCoordinator(this) }
}
