"""Security Alerts page: Search, filter, status workflow, export."""
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone

import config
from src.database import (
    search_alerts,
    get_alert,
    update_alert_status,
    bulk_update_status,
    export_alerts_csv,
    get_alert_counts,
    get_recent_runs,
)

st.set_page_config(page_title="Security Alerts", layout="wide")
st.title("🚨 Security Alerts")

# Alert counts
counts = get_alert_counts()
total = sum(counts["by_status"].values())

if total == 0:
    st.info("No alerts in database. Analyze traffic on the **Traffic Analysis** page and save alerts.")
    st.stop()

# KPI row
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Alerts", f"{total:,}")
c2.metric("Open", f"{counts['by_status'].get('New', 0) + counts['by_status'].get('Investigating', 0):,}")
c3.metric("Critical", f"{counts['by_risk'].get('Critical', 0):,}", delta_color="inverse")
c4.metric("High", f"{counts['by_risk'].get('High', 0):,}", delta_color="inverse")
c5.metric("Resolved", f"{counts['by_status'].get('Resolved', 0):,}")

st.divider()

# Filters
with st.expander("🔍 Filters", expanded=True):
    fcol1, fcol2, fcol3, fcol4, fcol5 = st.columns(5)

    status_options = ["All"] + sorted(counts["by_status"].keys())
    fcol1.selectbox("Status", status_options, key="alert_status")

    risk_options = ["All"] + sorted(counts["by_risk"].keys())
    fcol2.selectbox("Risk Level", risk_options, key="alert_risk")

    class_options = ["All"] + sorted(counts["by_class"].keys())
    fcol3.selectbox("Attack Class", class_options, key="alert_class")

    date_range = fcol4.date_input("Date Range", value=[], key="alert_date")

    fcol5.text_input("Search (IP, Port, Class)", key="alert_search")

# Search alerts
alerts = search_alerts(
    text=st.session_state.get("alert_search") or None,
    status=st.session_state.get("alert_status") if st.session_state.get("alert_status") != "All" else None,
    level=st.session_state.get("alert_risk") if st.session_state.get("alert_risk") != "All" else None,
    order_by="detected_at",
    desc=True,
    limit=1000,
)

# Date filter (client-side)
if st.session_state.get("alert_date") and len(st.session_state["alert_date"]) == 2:
    start, end = st.session_state["alert_date"]
    alerts = [
        a for a in alerts
        if start <= pd.to_datetime(a["detected_at"]).date() <= end
    ]

if st.session_state.get("alert_class", "All") != "All":
    alerts = [a for a in alerts if a["predicted_class"] == st.session_state["alert_class"]]

st.caption(f"Showing {len(alerts)} alerts")

# Alerts table with selection
if alerts:
    df = pd.DataFrame(alerts)

    # Add selection column
    df["select"] = False

    # Display columns
    display_cols = ["select", "alert_id", "detected_at", "source_ip", "dest_ip", "dest_port",
                    "protocol", "predicted_class", "confidence", "risk_score", "risk_level",
                    "status", "occurrence_count"]

    # Format for display
    display_df = df[display_cols].copy()
    display_df["detected_at"] = pd.to_datetime(display_df["detected_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
    display_df["confidence"] = display_df["confidence"].apply(lambda x: f"{x:.2%}")
    display_df["risk_score"] = display_df["risk_score"].apply(lambda x: f"{x:.1f}")

    # Editable table
    edited = st.data_editor(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "select": st.column_config.CheckboxColumn("Select", default=False),
            "alert_id": st.column_config.NumberColumn("ID", disabled=True),
            "detected_at": st.column_config.TextColumn("Detected", disabled=True),
            "source_ip": st.column_config.TextColumn("Src IP", disabled=True),
            "dest_ip": st.column_config.TextColumn("Dst IP", disabled=True),
            "dest_port": st.column_config.NumberColumn("Dst Port", disabled=True),
            "protocol": st.column_config.TextColumn("Proto", disabled=True),
            "predicted_class": st.column_config.TextColumn("Class", disabled=True),
            "confidence": st.column_config.TextColumn("Confidence", disabled=True),
            "risk_score": st.column_config.TextColumn("Risk Score", disabled=True),
            "risk_level": st.column_config.TextColumn("Risk", disabled=True),
            "status": st.column_config.TextColumn("Status", disabled=True),
            "occurrence_count": st.column_config.NumberColumn("Occurrences", disabled=True),
        },
        key="alerts_editor",
    )

    # Get selected alert IDs
    selected_ids = edited[edited["select"]]["alert_id"].tolist()

    # Bulk actions
    if selected_ids:
        st.divider()
        st.subheader("⚡ Bulk Actions")
        bcol1, bcol2, bcol3, bcol4 = st.columns(4)

        if bcol1.button("🔍 Mark Investigating", type="secondary", use_container_width=True):
            updated = bulk_update_status(selected_ids, "Investigating", "Bulk triage")
            st.success(f"Updated {updated} alerts to Investigating")
            st.rerun()

        if bcol2.button("✅ Mark Resolved", type="primary", use_container_width=True):
            updated = bulk_update_status(selected_ids, "Resolved", "Bulk resolved")
            st.success(f"Updated {updated} alerts to Resolved")
            st.rerun()

        if bcol3.button("🔄 Reopen", type="secondary", use_container_width=True):
            updated = bulk_update_status(selected_ids, "Investigating", "Reopened for review")
            st.success(f"Reopened {updated} alerts")
            st.rerun()

        # Export selected
        selected_alerts = [a for a in alerts if a["alert_id"] in selected_ids]
        csv = export_alerts_csv(selected_alerts)
        bcol4.download_button(
            "📥 Export Selected (CSV)",
            csv,
            f"alerts_selected_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            "text/csv",
            use_container_width=True,
        )

    # Export all
    st.divider()
    ecol1, ecol2 = st.columns(2)
    csv_all = export_alerts_csv(alerts)
    ecol1.download_button(
        "📥 Export All Filtered (CSV)",
        csv_all,
        f"alerts_all_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        "text/csv",
        use_container_width=True,
    )

    # Detail panel for single selection
    if len(selected_ids) == 1:
        alert = get_alert(selected_ids[0])
        if alert:
            st.divider()
            st.subheader(f"🔍 Alert #{alert['alert_id']} Details")

            dcol1, dcol2 = st.columns([1, 1])

            with dcol1:
                st.write("**Basic Information**")
                info_items = [
                    ("Alert ID", alert["alert_id"]),
                    ("Detected", pd.to_datetime(alert["detected_at"]).strftime("%Y-%m-%d %H:%M:%S")),
                    ("Source IP", alert.get("source_ip", "N/A")),
                    ("Dest IP", alert.get("dest_ip", "N/A")),
                    ("Dest Port", alert.get("dest_port", "N/A")),
                    ("Protocol", alert.get("protocol", "N/A")),
                    ("Predicted Class", alert["predicted_class"]),
                    ("Confidence", f"{alert['confidence']:.2%}"),
                    ("Anomaly Score", f"{alert.get('anomaly_score', 0):.3f}"),
                    ("Risk Score", f"{alert['risk_score']:.1f}"),
                    ("Risk Level", alert["risk_level"]),
                    ("Status", alert["status"]),
                    ("Occurrences", alert["occurrence_count"]),
                    ("First Seen", pd.to_datetime(alert["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")),
                    ("Last Seen", pd.to_datetime(alert["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")),
                    ("Source File", alert.get("source_file", "N/A")),
                    ("Model Version", alert.get("model_version", "N/A")),
                ]
                for label, value in info_items:
                    st.write(f"**{label}:** {value}")

            with dcol2:
                # Status transition
                st.write("**Status Update**")
                current_status = alert["status"]
                status_options = ["New", "Investigating", "Resolved"]
                if current_status == "Resolved":
                    status_options = ["Resolved", "Investigating"]  # Allow reopen

                new_status = st.selectbox(
                    "New Status",
                    status_options,
                    index=status_options.index(current_status),
                    key=f"status_select_{alert['alert_id']}",
                )

                note = st.text_area("Analyst Note", max_chars=1000, key=f"note_{alert['alert_id']}")

                if st.button("Update Status", type="primary", key=f"update_{alert['alert_id']}"):
                    if new_status != current_status:
                        success = update_alert_status(alert["alert_id"], new_status, note)
                        if success:
                            st.success(f"Status updated to {new_status}")
                            st.rerun()
                        else:
                            st.error("Failed to update status")

                # History
                st.write("**Status History**")
                from src.database import get_conn
                with get_conn() as conn:
                    history = conn.execute(
                        "SELECT * FROM alert_history WHERE alert_id = ? ORDER BY changed_at",
                        (alert["alert_id"],),
                    ).fetchall()

                if history:
                    hist_df = pd.DataFrame([dict(h) for h in history])
                    hist_df["changed_at"] = pd.to_datetime(hist_df["changed_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                    st.dataframe(hist_df[["changed_at", "old_status", "new_status", "note"]], hide_index=True, use_container_width=True)
                else:
                    st.caption("No status changes recorded")

                # Features JSON
                if alert.get("features_json"):
                    st.write("**Key Features**")
                    import json
                    try:
                        features = json.loads(alert["features_json"])
                        feat_df = pd.DataFrame(list(features.items()), columns=["Feature", "Value"])
                        st.dataframe(feat_df, hide_index=True, use_container_width=True)
                    except Exception:
                        st.caption("Features data unavailable")

# Alert metrics
st.divider()
st.subheader("📊 Alert Metrics")

mcol1, mcol2 = st.columns(2)

with mcol1:
    # Status pie
    if counts["by_status"]:
        fig = px.pie(
            values=list(counts["by_status"].values()),
            names=list(counts["by_status"].keys()),
            title="Alerts by Status",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        st.plotly_chart(fig, use_container_width=True)

with mcol2:
    # Risk level bar
    risk_order = ["Critical", "High", "Medium", "Low"]
    risk_colors = {"Critical": "#F85149", "High": "#F0883E", "Medium": "#D29922", "Low": "#2EA043"}
    risk_data = {k: counts["by_risk"].get(k, 0) for k in risk_order}
    fig = px.bar(
        x=list(risk_data.keys()),
        y=list(risk_data.values()),
        color=list(risk_data.keys()),
        color_discrete_map=risk_colors,
        title="Alerts by Risk Level",
    )
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

# Mean time to resolve
if counts["by_status"].get("Resolved", 0) > 0:
    from src.database import get_conn
    with get_conn() as conn:
        resolved = conn.execute(
            """SELECT alert_id, first_seen,
                      (SELECT changed_at FROM alert_history ah
                       WHERE ah.alert_id = a.alert_id AND ah.new_status = 'Resolved'
                       ORDER BY changed_at LIMIT 1) as resolved_at
               FROM alerts a WHERE status = 'Resolved'"""
        ).fetchall()

    if resolved:
        total_hours = 0
        count = 0
        for r in resolved:
            if r["resolved_at"]:
                first = pd.to_datetime(r["first_seen"])
                resolved_at = pd.to_datetime(r["resolved_at"])
                hours = (resolved_at - first).total_seconds() / 3600
                total_hours += hours
                count += 1
        if count > 0:
            st.metric("Mean Time to Resolve", f"{total_hours / count:.1f} hours")