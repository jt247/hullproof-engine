package com.acme.notes

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class ShareReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        NoteStore.save(intent.getStringExtra("text"))
    }
}
