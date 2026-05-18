from flask import (
    Flask,
    render_template,
    request,
    send_file
)

import requests
import concurrent.futures
import re
import os
import csv
import json
import http.client

from io import StringIO, BytesIO

# ==================================================
# Flask App
# ==================================================
app = Flask(__name__)

# ==================================================
# Config
# ==================================================
URL = "https://gql.aiq.netapp.com/"

PORT = int(
    os.environ.get("PORT", 5000)
)

session = requests.Session()

LAST_RESULTS = []

# ==================================================
# Cluster Naming Rules
# ==================================================
PATTERNS = [
    {
        "match": r"^(spfsc|spfscdr)",
        "format": "{cluster}-n{index:02d}"
    },
    {
        "match": r"^(mtkhwrd|mtkswrd|mtkoa|mtkdr|mtkia|mcp|mtp)",
        "format": "{cluster}_n{index:02d}"
    },
    {
        "match": r"^(nacmode|amcmode|nbt|ambt|TY)",
        "format": "{cluster}-{index:02d}"
    },
    {
        "match": r"^(tcfsc|dsfsc)",
        "format": "{cluster}n{index:02d}"
    }
]

# ==================================================
# Build Hostname
# ==================================================
def build_hostname(cluster, index):

    cluster = cluster.strip()

    for p in PATTERNS:

        if re.match(p["match"], cluster):

            return p["format"].format(
                cluster=cluster,
                index=index
            )

    return f"{cluster}{index:02d}"

# ==================================================
# Refresh Token
# ==================================================
def refresh_token():

    # ==========================================
    # Priority 1:
    # Railway Environment Variable
    # ==========================================
    refresh_token_value = os.environ.get(
        "REFRESH_TOKEN"
    )

    # ==========================================
    # Priority 2:
    # Local refresh_token.txt
    # ==========================================
    if not refresh_token_value:
        raise Exception("REFRESH_TOKEN not set in Railway Variables")

    # ==========================================
    # Request Access Token
    # ==========================================
    conn = http.client.HTTPSConnection(
        "api.activeiq.netapp.com"
    )

    payload = json.dumps({
        "refresh_token": refresh_token_value
    })

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    conn.request(
        "POST",
        "/v1/tokens/accessToken",
        payload,
        headers
    )

    res = conn.getresponse()

    data = res.read()

    response_json = json.loads(
        data.decode("utf-8")
    )

    access_token = response_json.get(
        "access_token"
    )

    if not access_token:

        raise Exception(
            f"Cannot get access token: {response_json}"
        )

    return access_token

# ==================================================
# Query Risk
# ==================================================
def get_risk(hostname, access_token):

    query = """
    query get_fail_disk($hostName: String) {
      risks(hostName: $hostName) {
        risks {
          riskId
          riskInstances {
            systemRiskDetail
            riskTriggeredDate
            riskLastTriggeredDate
          }
        }
      }
    }
    """

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    variables = {
        "hostName": hostname
    }

    try:

        r = session.post(
            URL,
            headers=headers,
            json={
                "query": query,
                "variables": variables
            },
            timeout=20
        )

        r.raise_for_status()

        data = r.json()

        risks = (
            data.get("data", {})
                .get("risks", {})
                .get("risks", [])
        )

        for risk in risks:

            if str(risk.get("riskId")) == "2703":

                instances = risk.get(
                    "riskInstances",
                    []
                )

                if not instances:

                    return {
                        "hostname": hostname,
                        "status": "FAIL DISK",
                        "detail": "No riskInstances",
                        "triggered": "",
                        "last_triggered": ""
                    }

                first = instances[0]

                return {
                    "hostname": hostname,
                    "status": "FAIL DISK",
                    "detail": first.get(
                        "systemRiskDetail"
                    ),
                    "triggered": first.get(
                        "riskTriggeredDate"
                    ),
                    "last_triggered": first.get(
                        "riskLastTriggeredDate"
                    )
                }

        return {
            "hostname": hostname,
            "status": "OK",
            "detail": "",
            "triggered": "",
            "last_triggered": ""
        }

    except Exception as e:

        return {
            "hostname": hostname,
            "status": "ERROR",
            "detail": str(e),
            "triggered": "",
            "last_triggered": ""
        }

# ==================================================
# Main Page
# ==================================================
@app.route("/", methods=["GET", "POST"])
def index():

    global LAST_RESULTS

    results = []

    if request.method == "POST":

        try:

            clusters = [
                c.strip()
                for c in request.form["clusters"].splitlines()
                if c.strip()
            ]

            max_node = int(
                request.form["max_node"]
            )

            # ==================================
            # Get Access Token
            # ==================================
            access_token = refresh_token()

            # ==================================
            # Build Hostnames
            # ==================================
            hostnames = [
                build_hostname(cluster, i)
                for cluster in clusters
                for i in range(1, max_node + 1)
            ]

            # ==================================
            # Concurrent Query
            # ==================================
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=3
            ) as executor:

                futures = [
                    executor.submit(
                        get_risk,
                        host,
                        access_token
                    )
                    for host in hostnames
                ]

                for future in concurrent.futures.as_completed(
                    futures
                ):

                    try:

                        result = future.result(
                            timeout=30
                        )

                        # Only show problem hosts
                        if result["status"] != "OK":

                            results.append(result)

                    except Exception as e:

                        results.append({
                            "hostname": "UNKNOWN",
                            "status": "ERROR",
                            "detail": str(e),
                            "triggered": "",
                            "last_triggered": ""
                        })

            # ==================================
            # Sort Results
            # ==================================
            results = sorted(
                results,
                key=lambda x: x["hostname"]
            )

            LAST_RESULTS = results

        except Exception as e:

            results.append({
                "hostname": "SYSTEM",
                "status": "ERROR",
                "detail": str(e),
                "triggered": "",
                "last_triggered": ""
            })

    return render_template(
        "index.html",
        results=results
    )

# ==================================================
# Export CSV
# ==================================================
@app.route("/export")
def export_csv():

    global LAST_RESULTS

    si = StringIO()

    cw = csv.writer(si)

    cw.writerow([
        "Hostname",
        "Status",
        "Detail",
        "Triggered",
        "Last Triggered"
    ])

    for r in LAST_RESULTS:

        cw.writerow([
            r["hostname"],
            r["status"],
            r["detail"],
            r["triggered"],
            r["last_triggered"]
        ])

    output = BytesIO()

    output.write(
        si.getvalue().encode("utf-8")
    )

    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="netapp_fail_disk.csv"
    )

# ==================================================
# Main
# ==================================================
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=PORT
    )
