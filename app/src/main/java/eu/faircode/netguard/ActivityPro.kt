package eu.faircode.netguard

import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Paint
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.*
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NavUtils

/*
   This file is part of NetGuard.

   NetGuard is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   NetGuard is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

   Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/   class ActivityPro : AppCompatActivity() {
    private var iab: IAB? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        Log.i(TAG, "Create")
        Util.setTheme(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.pro)
        supportActionBar!!.setTitle(R.string.title_pro)
        supportActionBar!!.setDisplayHomeAsUpEnabled(true)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN)

        // Initial state
        updateState()
        val tvLogTitle = findViewById<TextView>(R.id.tvLogTitle)
        val tvFilterTitle = findViewById<TextView>(R.id.tvFilterTitle)
        val tvNotifyTitle = findViewById<TextView>(R.id.tvNotifyTitle)
        val tvSpeedTitle = findViewById<TextView>(R.id.tvSpeedTitle)
        val tvThemeTitle = findViewById<TextView>(R.id.tvThemeTitle)
        val tvAllTitle = findViewById<TextView>(R.id.tvAllTitle)
        val tvDev1Title = findViewById<TextView>(R.id.tvDev1Title)
        val tvDev2Title = findViewById<TextView>(R.id.tvDev2Title)
        tvLogTitle.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvFilterTitle.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvNotifyTitle.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvSpeedTitle.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvThemeTitle.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvAllTitle.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvDev1Title.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        tvDev2Title.paintFlags = tvLogTitle.paintFlags or Paint.UNDERLINE_TEXT_FLAG
        val listener = View.OnClickListener { view ->
            val sku: String
            sku = when (view.id) {
                R.id.tvLogTitle -> SKU_LOG
                R.id.tvFilterTitle -> SKU_FILTER
                R.id.tvNotifyTitle -> SKU_NOTIFY
                R.id.tvSpeedTitle -> SKU_SPEED
                R.id.tvThemeTitle -> SKU_THEME
                R.id.tvAllTitle -> SKU_PRO1
                R.id.tvDev1Title -> SKU_SUPPORT1
                R.id.tvDev2Title -> SKU_SUPPORT2
                else -> SKU_PRO1
            }
            val intent = Intent(Intent.ACTION_VIEW)
            intent.data = Uri.parse("http://www.netguard.me/#$sku")
            if (intent.resolveActivity(packageManager) != null) startActivity(intent)
        }
        tvLogTitle.setOnClickListener(listener)
        tvFilterTitle.setOnClickListener(listener)
        tvNotifyTitle.setOnClickListener(listener)
        tvSpeedTitle.setOnClickListener(listener)
        tvThemeTitle.setOnClickListener(listener)
        tvAllTitle.setOnClickListener(listener)
        tvDev1Title.setOnClickListener(listener)
        tvDev2Title.setOnClickListener(listener)
        try {
            iab = IAB({ iab ->
                Log.i(TAG, "IAB ready")
                try {
                    iab.updatePurchases()
                    updateState()
                    val btnLog = findViewById<Button>(R.id.btnLog)
                    val btnFilter = findViewById<Button>(R.id.btnFilter)
                    val btnNotify = findViewById<Button>(R.id.btnNotify)
                    val btnSpeed = findViewById<Button>(R.id.btnSpeed)
                    val btnTheme = findViewById<Button>(R.id.btnTheme)
                    val btnAll = findViewById<Button>(R.id.btnAll)
                    val btnDev1 = findViewById<Button>(R.id.btnDev1)
                    val btnDev2 = findViewById<Button>(R.id.btnDev2)
                    val listener = View.OnClickListener { view ->
                        try {
                            var id = 0
                            var pi: PendingIntent? = null
                            if (view === btnLog) {
                                id = SKU_LOG_ID
                                pi = iab.getBuyIntent(SKU_LOG, false)
                            } else if (view === btnFilter) {
                                id = SKU_FILTER_ID
                                pi = iab.getBuyIntent(SKU_FILTER, false)
                            } else if (view === btnNotify) {
                                id = SKU_NOTIFY_ID
                                pi = iab.getBuyIntent(SKU_NOTIFY, false)
                            } else if (view === btnSpeed) {
                                id = SKU_SPEED_ID
                                pi = iab.getBuyIntent(SKU_SPEED, false)
                            } else if (view === btnTheme) {
                                id = SKU_THEME_ID
                                pi = iab.getBuyIntent(SKU_THEME, false)
                            } else if (view === btnAll) {
                                id = SKU_PRO1_ID
                                pi = iab.getBuyIntent(SKU_PRO1, false)
                            } else if (view === btnDev1) {
                                id = SKU_SUPPORT1_ID
                                pi = iab.getBuyIntent(SKU_SUPPORT1, true)
                            } else if (view === btnDev2) {
                                id = SKU_SUPPORT2_ID
                                pi = iab.getBuyIntent(SKU_SUPPORT2, true)
                            }
                            if (id > 0 && pi != null) startIntentSenderForResult(pi.intentSender, id, Intent(), 0, 0, 0)
                        } catch (ex: Throwable) {
                            Log.i(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                        }
                    }
                    btnLog.setOnClickListener(listener)
                    btnFilter.setOnClickListener(listener)
                    btnNotify.setOnClickListener(listener)
                    btnSpeed.setOnClickListener(listener)
                    btnTheme.setOnClickListener(listener)
                    btnAll.setOnClickListener(listener)
                    btnDev1.setOnClickListener(listener)
                    btnDev2.setOnClickListener(listener)
                    btnLog.isEnabled = true
                    btnFilter.isEnabled = true
                    btnNotify.isEnabled = true
                    btnSpeed.isEnabled = true
                    btnTheme.isEnabled = true
                    btnAll.isEnabled = true
                    btnDev1.isEnabled = true
                    btnDev2.isEnabled = true
                } catch (ex: Throwable) {
                    Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                }
            }, this)
            iab!!.bind()
        } catch (ex: Throwable) {
            Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
        }
    }

    override fun onDestroy() {
        Log.i(TAG, "Destroy")
        iab!!.unbind()
        iab = null
        super.onDestroy()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        val inflater = menuInflater
        inflater.inflate(R.menu.pro, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                Log.i(TAG, "Up")
                NavUtils.navigateUpFromSameTask(this)
                true
            }
            R.id.menu_challenge -> {
                menu_challenge()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        if (IAB.isPurchased(SKU_DONATION, this) || Util.isPlayStoreInstall(this)) menu.removeItem(R.id.menu_challenge)
        return super.onPrepareOptionsMenu(menu)
    }

    private fun menu_challenge() {
        val inflater = LayoutInflater.from(this)
        val view = inflater.inflate(R.layout.challenge, null, false)
        val dialog = AlertDialog.Builder(this)
                .setView(view)
                .setCancelable(true)
                .create()
        val android_id = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        val challenge = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) Build.SERIAL else "O3$android_id"
        val seed = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) "NetGuard2" else "NetGuard3"

        // Challenge
        val tvChallenge = view.findViewById<TextView>(R.id.tvChallenge)
        tvChallenge.text = challenge
        val ibCopy = view.findViewById<ImageButton>(R.id.ibCopy)
        ibCopy.setOnClickListener {
            val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText(getString(R.string.title_pro_challenge), challenge)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this@ActivityPro, android.R.string.copy, Toast.LENGTH_LONG).show()
        }

        // Response
        val etResponse = view.findViewById<EditText>(R.id.etResponse)
        try {
            val response = Util.md5(challenge, seed)
            etResponse.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {
                    // Do nothing
                }

                override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {
                    // Do nothing
                }

                override fun afterTextChanged(editable: Editable) {
                    if (response == editable.toString().toUpperCase()) {
                        IAB.setBought(SKU_DONATION, this@ActivityPro)
                        dialog.dismiss()
                        invalidateOptionsMenu()
                        updateState()
                    }
                }
            })
        } catch (ex: Throwable) {
            Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
        }
        val ibPaste = view.findViewById<ImageButton>(R.id.ibPaste)
        ibPaste.setOnClickListener {
            val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            if (clipboard != null &&
                    clipboard.hasPrimaryClip() &&
                    clipboard.primaryClipDescription!!.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)) {
                val item = clipboard.primaryClip!!.getItemAt(0)
                etResponse.setText(item.text.toString())
            }
        }
        dialog.show()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == RESULT_OK) {
            when (requestCode) {
                SKU_LOG_ID -> {
                    IAB.setBought(SKU_LOG, this)
                    updateState()
                }
                SKU_FILTER_ID -> {
                    IAB.setBought(SKU_FILTER, this)
                    updateState()
                }
                SKU_NOTIFY_ID -> {
                    IAB.setBought(SKU_NOTIFY, this)
                    updateState()
                }
                SKU_SPEED_ID -> {
                    IAB.setBought(SKU_SPEED, this)
                    updateState()
                }
                SKU_THEME_ID -> {
                    IAB.setBought(SKU_THEME, this)
                    updateState()
                }
                SKU_PRO1_ID -> {
                    IAB.setBought(SKU_PRO1, this)
                    updateState()
                }
                SKU_SUPPORT1_ID -> {
                    IAB.setBought(SKU_SUPPORT1, this)
                    updateState()
                }
                SKU_SUPPORT2_ID -> {
                    IAB.setBought(SKU_SUPPORT2, this)
                    updateState()
                }
            }
        }
    }

    private fun updateState() {
        val btnLog = findViewById<Button>(R.id.btnLog)
        val btnFilter = findViewById<Button>(R.id.btnFilter)
        val btnNotify = findViewById<Button>(R.id.btnNotify)
        val btnSpeed = findViewById<Button>(R.id.btnSpeed)
        val btnTheme = findViewById<Button>(R.id.btnTheme)
        val btnAll = findViewById<Button>(R.id.btnAll)
        val btnDev1 = findViewById<Button>(R.id.btnDev1)
        val btnDev2 = findViewById<Button>(R.id.btnDev2)
        val tvLog = findViewById<TextView>(R.id.tvLog)
        val tvFilter = findViewById<TextView>(R.id.tvFilter)
        val tvNotify = findViewById<TextView>(R.id.tvNotify)
        val tvSpeed = findViewById<TextView>(R.id.tvSpeed)
        val tvTheme = findViewById<TextView>(R.id.tvTheme)
        val tvAll = findViewById<TextView>(R.id.tvAll)
        val tvDev1 = findViewById<TextView>(R.id.tvDev1)
        val tvDev2 = findViewById<TextView>(R.id.tvDev2)
        val tvLogUnavailable = findViewById<TextView>(R.id.tvLogUnavailable)
        val tvFilterUnavailable = findViewById<TextView>(R.id.tvFilterUnavailable)
        val can = Util.canFilter(this)
        btnLog.visibility = if (IAB.isPurchased(SKU_LOG, this) || !can) View.GONE else View.VISIBLE
        btnFilter.visibility = if (IAB.isPurchased(SKU_FILTER, this) || !can) View.GONE else View.VISIBLE
        btnNotify.visibility = if (IAB.isPurchased(SKU_NOTIFY, this)) View.GONE else View.VISIBLE
        btnSpeed.visibility = if (IAB.isPurchased(SKU_SPEED, this)) View.GONE else View.VISIBLE
        btnTheme.visibility = if (IAB.isPurchased(SKU_THEME, this)) View.GONE else View.VISIBLE
        btnAll.visibility = if (IAB.isPurchased(SKU_PRO1, this)) View.GONE else View.VISIBLE
        btnDev1.visibility = if (IAB.isPurchased(SKU_SUPPORT1, this)) View.GONE else View.VISIBLE
        btnDev2.visibility = if (IAB.isPurchased(SKU_SUPPORT2, this)) View.GONE else View.VISIBLE
        tvLog.visibility = if (IAB.isPurchased(SKU_LOG, this) && can) View.VISIBLE else View.GONE
        tvFilter.visibility = if (IAB.isPurchased(SKU_FILTER, this) && can) View.VISIBLE else View.GONE
        tvNotify.visibility = if (IAB.isPurchased(SKU_NOTIFY, this)) View.VISIBLE else View.GONE
        tvSpeed.visibility = if (IAB.isPurchased(SKU_SPEED, this)) View.VISIBLE else View.GONE
        tvTheme.visibility = if (IAB.isPurchased(SKU_THEME, this)) View.VISIBLE else View.GONE
        tvAll.visibility = if (IAB.isPurchased(SKU_PRO1, this)) View.VISIBLE else View.GONE
        tvDev1.visibility = if (IAB.isPurchased(SKU_SUPPORT1, this)) View.VISIBLE else View.GONE
        tvDev2.visibility = if (IAB.isPurchased(SKU_SUPPORT2, this)) View.VISIBLE else View.GONE
        tvLogUnavailable.visibility = if (can) View.GONE else View.VISIBLE
        tvFilterUnavailable.visibility = if (can) View.GONE else View.VISIBLE
    }

    companion object {
        private const val TAG = "NetGuard.Pro"

        // adb shell pm clear com.android.vending
        // android.test.purchased
        private const val SKU_LOG_ID = 1
        private const val SKU_FILTER_ID = 2
        private const val SKU_NOTIFY_ID = 3
        private const val SKU_SPEED_ID = 4
        private const val SKU_THEME_ID = 5
        private const val SKU_PRO1_ID = 6
        private const val SKU_SUPPORT1_ID = 7
        private const val SKU_SUPPORT2_ID = 8
        const val SKU_LOG = "log"
        const val SKU_FILTER = "filter"
        const val SKU_NOTIFY = "notify"
        const val SKU_SPEED = "speed"
        const val SKU_THEME = "theme"
        const val SKU_PRO1 = "pro1"
        const val SKU_SUPPORT1 = "support1"
        const val SKU_SUPPORT2 = "support2"
        const val SKU_DONATION = "donation"
    }
}