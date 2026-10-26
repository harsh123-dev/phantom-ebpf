import json, urllib.request
url="http://127.0.0.1:9191/v1/receipts"
body={"run_id":"smoke-persistence-20261025T194800Z","scenario_id":"harmless-sink-restart-smoke","event_id":None,"workload":{"cluster":"phantom-k3s-lab","namespace":"phantom-eval","name":"recommendationservice-5dc98bbcb9-xq42k","image_digest":"sha256:149440c61b866ba5265959ea4ce2eb8864be9e4c8e0f6d5cc88546f899ecb8e7"},"processing_outcome":"smoke_only_no_experiment","provenance":{"classification":"non_experiment_smoke","ground_truth":"not_collected","purpose":"verify live sink persistence and retrieval"},"signed_observation":None}
req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"},method="POST")
with urllib.request.urlopen(req,timeout=10) as response:
    receipt=json.load(response)
    print("POST_STATUS",response.status)
    print("RECEIPT",json.dumps(receipt,sort_keys=True))
rid=receipt["receipt_id"]
for suffix in ("","/verify"):
    with urllib.request.urlopen(url+"/"+rid+suffix,timeout=10) as response:
        print("GET"+suffix,"STATUS",response.status,"BODY",response.read().decode())
