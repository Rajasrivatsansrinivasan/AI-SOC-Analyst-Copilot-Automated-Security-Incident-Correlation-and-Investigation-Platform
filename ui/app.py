import streamlit as st
import requests

API = st.sidebar.text_input("Backend API URL", "http://localhost:8000")

st.title("🔐 AI SOC Analyst Copilot (MVP)")

col1, col2 = st.columns(2)
with col1:
    if st.button("🔁 Rebuild Incidents (Correlate)"):
        r = requests.post(f"{API}/incidents/rebuild")
        st.success(r.json())

with col2:
    if st.button("📥 Load Incidents"):
        st.session_state["incidents"] = requests.get(f"{API}/incidents").json()

incidents = st.session_state.get("incidents", [])
if not incidents:
    st.info("Click **Load Incidents** after you seed alerts and rebuild incidents.")
else:
    st.subheader("Incidents")
    for inc in incidents:
        with st.expander(
            f"[{inc['severity'].upper()}] #{inc['id']} — {inc['title']} (Risk {inc['risk_score']})"
        ):
            st.code(inc["summary"])
            st.write(f"**Status:** {inc['status']} | **Verdict:** {inc['analyst_verdict']}")

            # Analyst fields
            notes = st.text_area("Analyst notes", inc["analyst_notes"], key=f"notes_{inc['id']}")
            verdict_options = ["unknown", "true_positive", "false_positive"]
            status_options = ["open", "triaged", "closed"]

            verdict = st.selectbox(
                "Verdict",
                verdict_options,
                index=verdict_options.index(inc["analyst_verdict"])
                if inc["analyst_verdict"] in verdict_options
                else 0,
                key=f"verdict_{inc['id']}",
            )

            status = st.selectbox(
                "Status",
                status_options,
                index=status_options.index(inc["status"])
                if inc["status"] in status_options
                else 0,
                key=f"status_{inc['id']}",
            )

            if st.button("💾 Save", key=f"save_{inc['id']}"):
                payload = {"analyst_notes": notes, "analyst_verdict": verdict, "status": status}
                resp = requests.patch(f"{API}/incidents/{inc['id']}", json=payload)
                if resp.ok:
                    st.success("Saved. Click **Load Incidents** to refresh.")
                else:
                    st.error(f"Save failed: {resp.status_code} {resp.text}")

            st.divider()

            # Alerts list
            st.markdown("### Alerts in this incident")
            for a in inc["alerts"]:
                st.write(
                    f"- `{a['ts']}` **{a['source']}** / `{a['alert_type']}` / **{a['severity']}** — {a['message']}"
                )

            st.divider()

            # Response Playbook (NEW)
            st.markdown("### Response Playbook")
            try:
                pb = requests.get(f"{API}/incidents/{inc['id']}/playbook")
                if pb.ok:
                    pb_json = pb.json()
                    steps = pb_json.get("steps", [])
                else:
                    steps = []
                    st.warning(f"Playbook fetch failed: {pb.status_code}")
            except Exception as e:
                steps = []
                st.warning(f"Playbook fetch error: {e}")

            if steps:
                for s in steps:
                    c1, c2, c3 = st.columns([2, 1, 3])
                    with c1:
                        st.write(f"**{s.get('action','')}**")
                    with c2:
                        st.write(s.get("risk", ""))
                    with c3:
                        st.write(s.get("impact", ""))

                action_choices = [s.get("action", "") for s in steps if s.get("action")]
                selected_action = st.selectbox(
                    "Simulate an action",
                    action_choices,
                    key=f"act_{inc['id']}",
                )

                if st.button("⚡ Simulate Remediation", key=f"sim_{inc['id']}"):
                    resp = requests.post(
                        f"{API}/incidents/{inc['id']}/simulate_remediate",
                        json={"action": selected_action},
                    )
                    if resp.ok:
                        st.success(resp.json())
                        st.info("Click **Load Incidents** to refresh notes/status.")
                    else:
                        st.error(f"Simulation failed: {resp.status_code} {resp.text}")
            else:
                st.info("No playbook steps available for this incident (or backend endpoint not added yet).")

            st.divider()

            # Export (NEW)
            st.markdown("### Export Incident")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("⬇️ Export JSON", key=f"export_{inc['id']}"):
                    resp = requests.get(f"{API}/incidents/{inc['id']}/export")
                    if resp.ok:
                        st.download_button(
                            label="Download incident.json",
                            data=resp.text,
                            file_name=f"incident_{inc['id']}.json",
                            mime="application/json",
                            key=f"dl_{inc['id']}",
                        )
                    else:
                        st.error(f"Export failed: {resp.status_code} {resp.text}")

            with c2:
                st.caption("Tip: Export is useful for reports and demo evidence.")
