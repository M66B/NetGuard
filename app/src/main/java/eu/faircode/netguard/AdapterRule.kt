package eu.faircode.netguard

import android.annotation.SuppressLint
import android.content.*
import android.database.Cursor
import android.graphics.Color
import android.graphics.Rect
import android.net.Uri
import android.os.AsyncTask
import android.os.Build
import android.provider.Settings
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ImageSpan
import android.util.Log
import android.util.TypedValue
import android.view.*
import android.widget.*
import android.widget.AdapterView.OnItemClickListener
import androidx.appcompat.app.AlertDialog
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.DrawableCompat
import androidx.preference.PreferenceManager
import androidx.recyclerview.widget.RecyclerView
import com.bumptech.glide.load.DecodeFormat
import com.bumptech.glide.request.RequestOptions
import eu.faircode.netguard.ActivityMain
import eu.faircode.netguard.ActivityPro
import eu.faircode.netguard.Util.DoubtListener
import java.text.SimpleDateFormat
import java.util.*

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
*/
class AdapterRule(context: Context, anchor: View) : RecyclerView.Adapter<AdapterRule.ViewHolder>(), Filterable {
    private val anchor: View
    private val inflater: LayoutInflater
    private var rv: RecyclerView? = null
    private var colorText = 0
    private var colorChanged = 0
    private val colorOn: Int
    private val colorOff: Int
    private val colorGrayed: Int
    private val iconSize: Int
    private var wifiActive = true
    private var otherActive = true
    var isLive = true
        private set
    private var listAll: List<Rule> = ArrayList()
    private var listFiltered: MutableList<Rule> = ArrayList()
    private val messaging = Arrays.asList(
            "com.discord",
            "com.facebook.mlite",
            "com.facebook.orca",
            "com.instagram.android",
            "com.Slack",
            "com.skype.raider",
            "com.snapchat.android",
            "com.whatsapp",
            "com.whatsapp.w4b"
    )
    private val download = Arrays.asList(
            "com.google.android.youtube"
    )

    class ViewHolder(var view: View) : RecyclerView.ViewHolder(view) {
        var llApplication: LinearLayout
        var ivIcon: ImageView
        var ivExpander: ImageView
        var tvName: TextView
        var tvHosts: TextView
        var rlLockdown: RelativeLayout
        var ivLockdown: ImageView
        var cbWifi: CheckBox
        var ivScreenWifi: ImageView
        var cbOther: CheckBox
        var ivScreenOther: ImageView
        var tvRoaming: TextView
        var tvRemarkMessaging: TextView
        var tvRemarkDownload: TextView
        var llConfiguration: LinearLayout
        var tvUid: TextView
        var tvPackage: TextView
        var tvVersion: TextView
        var tvInternet: TextView
        var tvDisabled: TextView
        var btnRelated: Button
        var ibSettings: ImageButton
        var ibLaunch: ImageButton
        var cbApply: CheckBox
        var llScreenWifi: LinearLayout
        var ivWifiLegend: ImageView
        var cbScreenWifi: CheckBox
        var llScreenOther: LinearLayout
        var ivOtherLegend: ImageView
        var cbScreenOther: CheckBox
        var cbRoaming: CheckBox
        var cbLockdown: CheckBox
        var ivLockdownLegend: ImageView
        var btnClear: ImageButton
        var llFilter: LinearLayout
        var ivLive: ImageView
        var tvLogging: TextView
        var btnLogging: Button
        var lvAccess: ListView
        var btnClearAccess: ImageButton
        var cbNotify: CheckBox

        init {
            llApplication = itemView.findViewById(R.id.llApplication)
            ivIcon = itemView.findViewById(R.id.ivIcon)
            ivExpander = itemView.findViewById(R.id.ivExpander)
            tvName = itemView.findViewById(R.id.tvName)
            tvHosts = itemView.findViewById(R.id.tvHosts)
            rlLockdown = itemView.findViewById(R.id.rlLockdown)
            ivLockdown = itemView.findViewById(R.id.ivLockdown)
            cbWifi = itemView.findViewById(R.id.cbWifi)
            ivScreenWifi = itemView.findViewById(R.id.ivScreenWifi)
            cbOther = itemView.findViewById(R.id.cbOther)
            ivScreenOther = itemView.findViewById(R.id.ivScreenOther)
            tvRoaming = itemView.findViewById(R.id.tvRoaming)
            tvRemarkMessaging = itemView.findViewById(R.id.tvRemarkMessaging)
            tvRemarkDownload = itemView.findViewById(R.id.tvRemarkDownload)
            llConfiguration = itemView.findViewById(R.id.llConfiguration)
            tvUid = itemView.findViewById(R.id.tvUid)
            tvPackage = itemView.findViewById(R.id.tvPackage)
            tvVersion = itemView.findViewById(R.id.tvVersion)
            tvInternet = itemView.findViewById(R.id.tvInternet)
            tvDisabled = itemView.findViewById(R.id.tvDisabled)
            btnRelated = itemView.findViewById(R.id.btnRelated)
            ibSettings = itemView.findViewById(R.id.ibSettings)
            ibLaunch = itemView.findViewById(R.id.ibLaunch)
            cbApply = itemView.findViewById(R.id.cbApply)
            llScreenWifi = itemView.findViewById(R.id.llScreenWifi)
            ivWifiLegend = itemView.findViewById(R.id.ivWifiLegend)
            cbScreenWifi = itemView.findViewById(R.id.cbScreenWifi)
            llScreenOther = itemView.findViewById(R.id.llScreenOther)
            ivOtherLegend = itemView.findViewById(R.id.ivOtherLegend)
            cbScreenOther = itemView.findViewById(R.id.cbScreenOther)
            cbRoaming = itemView.findViewById(R.id.cbRoaming)
            cbLockdown = itemView.findViewById(R.id.cbLockdown)
            ivLockdownLegend = itemView.findViewById(R.id.ivLockdownLegend)
            btnClear = itemView.findViewById(R.id.btnClear)
            llFilter = itemView.findViewById(R.id.llFilter)
            ivLive = itemView.findViewById(R.id.ivLive)
            tvLogging = itemView.findViewById(R.id.tvLogging)
            btnLogging = itemView.findViewById(R.id.btnLogging)
            lvAccess = itemView.findViewById(R.id.lvAccess)
            btnClearAccess = itemView.findViewById(R.id.btnClearAccess)
            cbNotify = itemView.findViewById(R.id.cbNotify)
            val wifiParent = cbWifi.parent as View
            wifiParent.post {
                val rect = Rect()
                cbWifi.getHitRect(rect)
                rect.bottom += rect.top
                rect.right += rect.left
                rect.top = 0
                rect.left = 0
                wifiParent.touchDelegate = TouchDelegate(rect, cbWifi)
            }
            val otherParent = cbOther.parent as View
            otherParent.post {
                val rect = Rect()
                cbOther.getHitRect(rect)
                rect.bottom += rect.top
                rect.right += rect.left
                rect.top = 0
                rect.left = 0
                otherParent.touchDelegate = TouchDelegate(rect, cbOther)
            }
        }
    }

    fun set(listRule: List<Rule>) {
        listAll = listRule
        listFiltered = ArrayList()
        listFiltered.addAll(listRule)
        notifyDataSetChanged()
    }

    fun setWifiActive() {
        wifiActive = true
        otherActive = false
        notifyDataSetChanged()
    }

    fun setMobileActive() {
        wifiActive = false
        otherActive = true
        notifyDataSetChanged()
    }

    fun setDisconnected() {
        wifiActive = false
        otherActive = false
        notifyDataSetChanged()
    }

    override fun onAttachedToRecyclerView(recyclerView: RecyclerView) {
        super.onAttachedToRecyclerView(recyclerView)
        rv = recyclerView
    }

    override fun onDetachedFromRecyclerView(recyclerView: RecyclerView) {
        super.onDetachedFromRecyclerView(recyclerView)
        rv = null
    }

    @SuppressLint("SetTextI18n")
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val context = holder.itemView.context
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        val log_app = prefs.getBoolean("log_app", false)
        val filter = prefs.getBoolean("filter", false)
        val notify_access = prefs.getBoolean("notify_access", false)

        // Get rule
        val rule = listFiltered[position]

        // Handle expanding/collapsing
        holder.llApplication.setOnClickListener {
            rule.expanded = !rule.expanded
            notifyItemChanged(holder.adapterPosition)
        }

        // Show if non default rules
        holder.itemView.setBackgroundColor(if (rule.changed) colorChanged else Color.TRANSPARENT)

        // Show expand/collapse indicator
        holder.ivExpander.setImageLevel(if (rule.expanded) 1 else 0)

        // Show application icon
        if (rule.icon <= 0) holder.ivIcon.setImageResource(android.R.drawable.sym_def_app_icon) else {
            val uri = Uri.parse("android.resource://" + rule.packageName + "/" + rule.icon)
            GlideApp.with(holder.itemView.context)
                    .applyDefaultRequestOptions(RequestOptions().format(DecodeFormat.PREFER_RGB_565))
                    .load(uri) //.diskCacheStrategy(DiskCacheStrategy.NONE)
                    //.skipMemoryCache(true)
                    .override(iconSize, iconSize)
                    .into(holder.ivIcon)
        }

        // Show application label
        holder.tvName.text = rule.name

        // Show application state
        var color = if (rule.system) colorOff else colorText
        if (!rule.internet || !rule.enabled) color = Color.argb(128, Color.red(color), Color.green(color), Color.blue(color))
        holder.tvName.setTextColor(color)
        holder.tvHosts.visibility = if (rule.hosts > 0) View.VISIBLE else View.GONE
        holder.tvHosts.text = java.lang.Long.toString(rule.hosts)

        // Lockdown settings
        var lockdown = prefs.getBoolean("lockdown", false)
        val lockdown_wifi = prefs.getBoolean("lockdown_wifi", true)
        val lockdown_other = prefs.getBoolean("lockdown_other", true)
        if (otherActive && !lockdown_other || wifiActive && !lockdown_wifi) lockdown = false
        holder.rlLockdown.visibility = if (lockdown && !rule.lockdown) View.VISIBLE else View.GONE
        holder.ivLockdown.isEnabled = rule.apply
        val screen_on = prefs.getBoolean("screen_on", true)

        // Wi-Fi settings
        holder.cbWifi.isEnabled = rule.apply
        holder.cbWifi.alpha = if (wifiActive) 1f else 0.5f
        holder.cbWifi.setOnCheckedChangeListener(null)
        holder.cbWifi.isChecked = rule.wifi_blocked
        holder.cbWifi.setOnCheckedChangeListener { compoundButton, isChecked ->
            rule.wifi_blocked = isChecked
            updateRule(context, rule, true, listAll)
        }
        holder.ivScreenWifi.isEnabled = rule.apply
        holder.ivScreenWifi.alpha = if (wifiActive) 1f else 0.5f
        holder.ivScreenWifi.visibility = if (rule.screen_wifi && rule.wifi_blocked) View.VISIBLE else View.INVISIBLE

        // Mobile settings
        holder.cbOther.isEnabled = rule.apply
        holder.cbOther.alpha = (if (otherActive) 1f else 0.5f)
        holder.cbOther.setOnCheckedChangeListener(null)
        holder.cbOther.isChecked = rule.other_blocked
        holder.cbOther.setOnCheckedChangeListener { compoundButton, isChecked ->
            rule.other_blocked = isChecked
            updateRule(context, rule, true, listAll)
        }
        holder.ivScreenOther.isEnabled = rule.apply
        holder.ivScreenOther.alpha = (if (otherActive) 1f else 0.5f)
        holder.ivScreenOther.visibility = if (rule.screen_other && rule.other_blocked) View.VISIBLE else View.INVISIBLE
        holder.tvRoaming.setTextColor(if (rule.apply) colorOff else colorGrayed)
        holder.tvRoaming.setAlpha(if (otherActive) 1f else 0.5f)
        holder.tvRoaming.visibility = if (rule.roaming && (!rule.other_blocked || rule.screen_other)) View.VISIBLE else View.INVISIBLE
        holder.tvRemarkMessaging.visibility = if (messaging.contains(rule.packageName)) View.VISIBLE else View.GONE
        holder.tvRemarkDownload.visibility = if (download.contains(rule.packageName)) View.VISIBLE else View.GONE

        // Expanded configuration section
        holder.llConfiguration.visibility = if (rule.expanded) View.VISIBLE else View.GONE

        // Show application details
        holder.tvUid.text = Integer.toString(rule.uid)
        holder.tvPackage.text = rule.packageName
        holder.tvVersion.text = rule.version

        // Show application state
        holder.tvInternet.visibility = if (rule.internet) View.GONE else View.VISIBLE
        holder.tvDisabled.visibility = if (rule.enabled) View.GONE else View.VISIBLE

        // Show related
        holder.btnRelated.visibility = if (rule.relateduids) View.VISIBLE else View.GONE
        holder.btnRelated.setOnClickListener {
            val main = Intent(context, ActivityMain::class.java)
            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(rule.uid))
            main.putExtra(ActivityMain.EXTRA_RELATED, true)
            context.startActivity(main)
        }

        // Launch application settings
        if (rule.expanded) {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            intent.data = Uri.parse("package:" + rule.packageName)
            val settings = if (intent.resolveActivity(context.packageManager) == null) null else intent
            holder.ibSettings.visibility = if (settings == null) View.GONE else View.VISIBLE
            holder.ibSettings.setOnClickListener { context.startActivity(settings) }
        } else holder.ibSettings.visibility = View.GONE

        // Launch application
        if (rule.expanded) {
            val intent = context.packageManager.getLaunchIntentForPackage(rule.packageName)
            val launch = if (intent?.resolveActivity(context.packageManager) == null) null else intent
            holder.ibLaunch.visibility = if (launch == null) View.GONE else View.VISIBLE
            holder.ibLaunch.setOnClickListener { context.startActivity(launch) }
        } else holder.ibLaunch.visibility = View.GONE

        // Apply
        holder.cbApply.isEnabled = rule.pkg && filter
        holder.cbApply.setOnCheckedChangeListener(null)
        holder.cbApply.isChecked = rule.apply
        holder.cbApply.setOnCheckedChangeListener { compoundButton, isChecked ->
            rule.apply = isChecked
            updateRule(context, rule, true, listAll)
        }

        // Show Wi-Fi screen on condition
        holder.llScreenWifi.visibility = if (screen_on) View.VISIBLE else View.GONE
        holder.cbScreenWifi.isEnabled = rule.wifi_blocked && rule.apply
        holder.cbScreenWifi.setOnCheckedChangeListener(null)
        holder.cbScreenWifi.isChecked = rule.screen_wifi
        holder.cbScreenWifi.setOnCheckedChangeListener { buttonView, isChecked ->
            rule.screen_wifi = isChecked
            updateRule(context, rule, true, listAll)
        }

        // Show mobile screen on condition
        holder.llScreenOther.visibility = if (screen_on) View.VISIBLE else View.GONE
        holder.cbScreenOther.isEnabled = rule.other_blocked && rule.apply
        holder.cbScreenOther.setOnCheckedChangeListener(null)
        holder.cbScreenOther.isChecked = rule.screen_other
        holder.cbScreenOther.setOnCheckedChangeListener { buttonView, isChecked ->
            rule.screen_other = isChecked
            updateRule(context, rule, true, listAll)
        }

        // Show roaming condition
        holder.cbRoaming.isEnabled = (!rule.other_blocked || rule.screen_other) && rule.apply
        holder.cbRoaming.setOnCheckedChangeListener(null)
        holder.cbRoaming.isChecked = rule.roaming
        holder.cbRoaming.setOnCheckedChangeListener { buttonView, isChecked ->
            rule.roaming = isChecked
            updateRule(context, rule, true, listAll)
        }

        // Show lockdown
        holder.cbLockdown.isEnabled = rule.apply
        holder.cbLockdown.setOnCheckedChangeListener(null)
        holder.cbLockdown.isChecked = rule.lockdown
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            val wrap = DrawableCompat.wrap(holder.ivLockdownLegend.drawable)
            DrawableCompat.setTint(wrap, colorOn)
        }
        holder.cbLockdown.setOnCheckedChangeListener { buttonView, isChecked ->
            rule.lockdown = isChecked
            updateRule(context, rule, true, listAll)
        }

        // Reset rule
        holder.btnClear.setOnClickListener { view ->
            Util.areYouSure(view.context, R.string.msg_clear_rules) {
                holder.cbApply.isChecked = true
                holder.cbWifi.isChecked = rule.wifi_default
                holder.cbOther.isChecked = rule.other_default
                holder.cbScreenWifi.isChecked = rule.screen_wifi_default
                holder.cbScreenOther.isChecked = rule.screen_other_default
                holder.cbRoaming.isChecked = rule.roaming_default
                holder.cbLockdown.isChecked = false
            }
        }
        holder.llFilter.visibility = if (Util.canFilter(context)) View.VISIBLE else View.GONE

        // Live
        holder.ivLive.setOnClickListener(object : View.OnClickListener {
            override fun onClick(view: View) {
                isLive = !isLive
                val tv = TypedValue()
                view.context.theme.resolveAttribute(if (isLive) R.attr.iconPause else R.attr.iconPlay, tv, true)
                holder.ivLive.setImageResource(tv.resourceId)
                if (isLive) notifyDataSetChanged()
            }
        })

        // Show logging/filtering is disabled
        holder.tvLogging.setText(if (log_app && filter) R.string.title_logging_enabled else R.string.title_logging_disabled)
        holder.btnLogging.setOnClickListener {
            val inflater = LayoutInflater.from(context)
            val view = inflater.inflate(R.layout.enable, null, false)
            val cbLogging = view.findViewById<CheckBox>(R.id.cbLogging)
            val cbFiltering = view.findViewById<CheckBox>(R.id.cbFiltering)
            val cbNotify = view.findViewById<CheckBox>(R.id.cbNotify)
            val tvFilter4 = view.findViewById<TextView>(R.id.tvFilter4)
            cbLogging.isChecked = log_app
            cbFiltering.isChecked = filter
            cbFiltering.isEnabled = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP
            tvFilter4.visibility = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) View.GONE else View.VISIBLE
            cbNotify.isChecked = notify_access
            cbNotify.isEnabled = log_app
            cbLogging.setOnCheckedChangeListener { compoundButton, checked ->
                prefs.edit().putBoolean("log_app", checked).apply()
                cbNotify.isEnabled = checked
                if (!checked) {
                    cbNotify.isChecked = false
                    prefs.edit().putBoolean("notify_access", false).apply()
                    ServiceSinkhole.reload("changed notify", context, false)
                }
                notifyDataSetChanged()
            }
            cbFiltering.setOnCheckedChangeListener { compoundButton, checked ->
                if (checked) cbLogging.isChecked = true
                prefs.edit().putBoolean("filter", checked).apply()
                ServiceSinkhole.reload("changed filter", context, false)
                notifyDataSetChanged()
            }
            cbNotify.setOnCheckedChangeListener { compoundButton, checked ->
                prefs.edit().putBoolean("notify_access", checked).apply()
                ServiceSinkhole.reload("changed notify", context, false)
                notifyDataSetChanged()
            }
            val dialog = AlertDialog.Builder(context)
                    .setView(view)
                    .setCancelable(true)
                    .create()
            dialog.show()
        }

        // Show access rules
        if (rule.expanded) {
            // Access the database when expanded only
            val badapter = DatabaseHelper.getInstance(context)?.let {
                AdapterAccess(context,
                        it.getAccess(rule.uid))
            }
            holder.lvAccess.onItemClickListener = OnItemClickListener { parent, view, bposition, bid ->
                val pm = context.packageManager
                val cursor = badapter?.getItem(bposition) as Cursor
                val id = cursor.getLong(cursor.getColumnIndex("ID"))
                val version = cursor.getInt(cursor.getColumnIndex("version"))
                val protocol = cursor.getInt(cursor.getColumnIndex("protocol"))
                val daddr = cursor.getString(cursor.getColumnIndex("daddr"))
                val dport = cursor.getInt(cursor.getColumnIndex("dport"))
                val time = cursor.getLong(cursor.getColumnIndex("time"))
                val block = cursor.getInt(cursor.getColumnIndex("block"))
                val popup = PopupMenu(context, anchor)
                popup.inflate(R.menu.access)
                popup.menu.findItem(R.id.menu_host).title = Util.getProtocolName(protocol, version, false) + " " +
                        daddr + if (dport > 0) "/$dport" else ""
                val sub = popup.menu.findItem(R.id.menu_host).subMenu
                var multiple = false
                var alt: Cursor? = null
                try {
                    alt = DatabaseHelper.getInstance(context)?.getAlternateQNames(daddr)
                    if (alt != null) {
                        while (alt.moveToNext()) {
                            multiple = true
                            sub.add(Menu.NONE, Menu.NONE, 0, alt.getString(0)).isEnabled = false
                        }
                    }
                } finally {
                    alt?.close()
                }
                popup.menu.findItem(R.id.menu_host).isEnabled = multiple
                markPro(context, popup.menu.findItem(R.id.menu_allow), ActivityPro.SKU_FILTER)
                markPro(context, popup.menu.findItem(R.id.menu_block), ActivityPro.SKU_FILTER)

                // Whois
                val lookupIP = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.dnslytics.com/whois-lookup/$daddr"))
                if (pm.resolveActivity(lookupIP, 0) == null) popup.menu.removeItem(R.id.menu_whois) else popup.menu.findItem(R.id.menu_whois).title = context.getString(R.string.title_log_whois, daddr)

                // Lookup port
                val lookupPort = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.speedguide.net/port.php?port=$dport"))
                if (dport <= 0 || pm.resolveActivity(lookupPort, 0) == null) popup.menu.removeItem(R.id.menu_port) else popup.menu.findItem(R.id.menu_port).title = context.getString(R.string.title_log_port, dport)
                popup.menu.findItem(R.id.menu_time).title = SimpleDateFormat.getDateTimeInstance().format(time)
                popup.setOnMenuItemClickListener(PopupMenu.OnMenuItemClickListener { menuItem ->
                    val menu = menuItem.itemId
                    var result = false
                    when (menu) {
                        R.id.menu_whois -> {
                            context.startActivity(lookupIP)
                            result = true
                        }
                        R.id.menu_port -> {
                            context.startActivity(lookupPort)
                            result = true
                        }
                        R.id.menu_allow -> {
                            if (IAB.isPurchased(ActivityPro.SKU_FILTER, context)) {
                                DatabaseHelper.getInstance(context)?.setAccess(id, 0)
                                ServiceSinkhole.reload("allow host", context, false)
                            } else context.startActivity(Intent(context, ActivityPro::class.java))
                            result = true
                        }
                        R.id.menu_block -> {
                            if (IAB.isPurchased(ActivityPro.SKU_FILTER, context)) {
                                DatabaseHelper.getInstance(context)?.setAccess(id, 1)
                                ServiceSinkhole.reload("block host", context, false)
                            } else context.startActivity(Intent(context, ActivityPro::class.java))
                            result = true
                        }
                        R.id.menu_reset -> {
                            DatabaseHelper.getInstance(context)?.setAccess(id, -1)
                            ServiceSinkhole.reload("reset host", context, false)
                            result = true
                        }
                        R.id.menu_copy -> {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = ClipData.newPlainText("netguard", daddr)
                            clipboard.setPrimaryClip(clip)
                            return@OnMenuItemClickListener true
                        }
                    }
                    if (menu == R.id.menu_allow || menu == R.id.menu_block || menu == R.id.menu_reset) object : AsyncTask<Any?, Any?, Long>() {
                        protected override fun doInBackground(vararg params: Any?): Long? {
                            return DatabaseHelper.getInstance(context)?.getHostCount(rule.uid, false)
                        }

                        override fun onPostExecute(hosts: Long) {
                            rule.hosts = hosts
                            notifyDataSetChanged()
                        }
                    }.execute()
                    result
                })
                if (block == 0) popup.menu.removeItem(R.id.menu_allow) else if (block == 1) popup.menu.removeItem(R.id.menu_block)
                popup.show()
            }
            holder.lvAccess.adapter = badapter
        } else {
            holder.lvAccess.adapter = null
            holder.lvAccess.onItemClickListener = null
        }

        // Clear access log
        holder.btnClearAccess.setOnClickListener { view ->
            Util.areYouSure(view.context, R.string.msg_reset_access) {
                DatabaseHelper.getInstance(context)?.clearAccess(rule.uid, true)
                if (!isLive) notifyDataSetChanged()
                if (rv != null) rv!!.scrollToPosition(holder.adapterPosition)
            }
        }

        // Notify on access
        holder.cbNotify.isEnabled = prefs.getBoolean("notify_access", false) && rule.apply
        holder.cbNotify.setOnCheckedChangeListener(null)
        holder.cbNotify.isChecked = rule.notify
        holder.cbNotify.setOnCheckedChangeListener { compoundButton, isChecked ->
            rule.notify = isChecked
            updateRule(context, rule, true, listAll)
        }
    }

    override fun onViewRecycled(holder: ViewHolder) {
        super.onViewRecycled(holder)

        //Context context = holder.itemView.getContext();
        //GlideApp.with(context).clear(holder.ivIcon);
        val adapter = holder.lvAccess.adapter as CursorAdapter?
        Log.i(TAG, "Closing access cursor")
        adapter?.changeCursor(null)
        holder.lvAccess.adapter = null
    }

    private fun markPro(context: Context, menu: MenuItem, sku: String?) {
        if (sku == null || !IAB.isPurchased(sku, context)) {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val dark = prefs.getBoolean("dark_theme", false)
            val ssb = SpannableStringBuilder("  " + menu.title)
            ssb.setSpan(ImageSpan(context, if (dark) R.drawable.ic_shopping_cart_white_24dp else R.drawable.ic_shopping_cart_black_24dp), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            menu.title = ssb
        }
    }

    private fun updateRule(context: Context, rule: Rule, root: Boolean, listAll: List<Rule>) {
        val wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE)
        val other = context.getSharedPreferences("other", Context.MODE_PRIVATE)
        val apply = context.getSharedPreferences("apply", Context.MODE_PRIVATE)
        val screen_wifi = context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE)
        val screen_other = context.getSharedPreferences("screen_other", Context.MODE_PRIVATE)
        val roaming = context.getSharedPreferences("roaming", Context.MODE_PRIVATE)
        val lockdown = context.getSharedPreferences("lockdown", Context.MODE_PRIVATE)
        val notify = context.getSharedPreferences("notify", Context.MODE_PRIVATE)
        if (rule.wifi_blocked == rule.wifi_default) wifi.edit().remove(rule.packageName).apply() else wifi.edit().putBoolean(rule.packageName, rule.wifi_blocked).apply()
        if (rule.other_blocked == rule.other_default) other.edit().remove(rule.packageName).apply() else other.edit().putBoolean(rule.packageName, rule.other_blocked).apply()
        if (rule.apply) apply.edit().remove(rule.packageName).apply() else apply.edit().putBoolean(rule.packageName, rule.apply).apply()
        if (rule.screen_wifi == rule.screen_wifi_default) screen_wifi.edit().remove(rule.packageName).apply() else screen_wifi.edit().putBoolean(rule.packageName, rule.screen_wifi).apply()
        if (rule.screen_other == rule.screen_other_default) screen_other.edit().remove(rule.packageName).apply() else screen_other.edit().putBoolean(rule.packageName, rule.screen_other).apply()
        if (rule.roaming == rule.roaming_default) roaming.edit().remove(rule.packageName).apply() else roaming.edit().putBoolean(rule.packageName, rule.roaming).apply()
        if (rule.lockdown) lockdown.edit().putBoolean(rule.packageName, rule.lockdown).apply() else lockdown.edit().remove(rule.packageName).apply()
        if (rule.notify) notify.edit().remove(rule.packageName).apply() else notify.edit().putBoolean(rule.packageName, rule.notify).apply()
        rule.updateChanged(context)
        Log.i(TAG, "Updated $rule")
        val listModified: MutableList<Rule> = ArrayList()
        for (pkg in rule.related) {
            for (related in listAll) if (related.packageName == pkg) {
                related.wifi_blocked = rule.wifi_blocked
                related.other_blocked = rule.other_blocked
                related.apply = rule.apply
                related.screen_wifi = rule.screen_wifi
                related.screen_other = rule.screen_other
                related.roaming = rule.roaming
                related.lockdown = rule.lockdown
                related.notify = rule.notify
                listModified.add(related)
            }
        }
        val listSearch: MutableList<Rule> = if (root) ArrayList(listAll) else listAll as MutableList<Rule>
        listSearch.remove(rule)
        for (modified in listModified) listSearch.remove(modified)
        for (modified in listModified) updateRule(context, modified, false, listSearch)
        if (root) {
            notifyDataSetChanged()
            NotificationManagerCompat.from(context).cancel(rule.uid)
            ServiceSinkhole.reload("rule changed", context, false)
        }
    }

    override fun getFilter(): Filter {
        return object : Filter() {
            override fun performFiltering(query: CharSequence): FilterResults {
                var query: CharSequence? = query
                val listResult: MutableList<Rule> = ArrayList()
                if (query == null) listResult.addAll(listAll) else {
                    query = query.toString().toLowerCase().trim { it <= ' ' }
                    val uid: Int
                    uid = try {
                        query.toString().toInt()
                    } catch (ignore: NumberFormatException) {
                        -1
                    }
                    for (rule in listAll) if (rule.uid == uid ||
                            rule.packageName.toLowerCase().contains(query) ||
                            rule.name != null && rule.name.toLowerCase().contains(query)) listResult.add(rule)
                }
                val result = FilterResults()
                result.values = listResult
                result.count = listResult.size
                return result
            }

            override fun publishResults(query: CharSequence, result: FilterResults) {
                listFiltered.clear()
                if (result == null) listFiltered.addAll(listAll) else {
                    listFiltered.addAll((result.values as List<Rule>))
                    if (listFiltered.size == 1) listFiltered[0].expanded = true
                }
                notifyDataSetChanged()
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        return ViewHolder(inflater.inflate(R.layout.rule, parent, false))
    }

    override fun getItemId(position: Int): Long {
        val rule = listFiltered[position]
        return rule.packageName.hashCode() * 100000L + rule.uid
    }

    override fun getItemCount(): Int {
        return listFiltered.size
    }

    companion object {
        private const val TAG = "NetGuard.Adapter"
    }

    init {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        this.anchor = anchor
        inflater = LayoutInflater.from(context)
        colorChanged = if (prefs.getBoolean("dark_theme", false)) Color.argb(128, Color.red(Color.DKGRAY), Color.green(Color.DKGRAY), Color.blue(Color.DKGRAY)) else Color.argb(128, Color.red(Color.LTGRAY), Color.green(Color.LTGRAY), Color.blue(Color.LTGRAY))
        val ta = context.theme.obtainStyledAttributes(intArrayOf(android.R.attr.textColorPrimary))
        colorText = try {
            ta.getColor(0, 0)
        } finally {
            ta.recycle()
        }
        val tv = TypedValue()
        context.theme.resolveAttribute(R.attr.colorOn, tv, true)
        colorOn = tv.data
        context.theme.resolveAttribute(R.attr.colorOff, tv, true)
        colorOff = tv.data
        colorGrayed = ContextCompat.getColor(context, R.color.colorGrayed)
        val typedValue = TypedValue()
        context.theme.resolveAttribute(android.R.attr.listPreferredItemHeight, typedValue, true)
        val height = TypedValue.complexToDimensionPixelSize(typedValue.data, context.resources.displayMetrics)
        iconSize = Math.round(height * context.resources.displayMetrics.density + 0.5f)
        setHasStableIds(true)
    }
}