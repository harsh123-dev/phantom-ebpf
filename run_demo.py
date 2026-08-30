import logging
import time
from research.evaluation.attacks.solarwinds_style import SolarWindsStyleAttack
from research.evaluation.attacks.dependency_confusion import DependencyConfusionAttack
from research.evaluation.attacks.xzutils_style import XZUtilsStyleAttack

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def run_solarwinds_attack():
    print("=========================================================")
    print("Initiating SolarWinds-style Build Tampering Attack Demo")
    print("=========================================================")
    attack = SolarWindsStyleAttack()
    
    print("\n[+] Injecting attack (building image & deploying)...")
    success = attack.inject(target_namespace="phantom-eval", pod_name="emailservice")
    
    if not success:
        print("[-] Injection failed.")
        return

    print("\n[+] Waiting 15 seconds for pod to settle...")
    time.sleep(15)
    
    print("\n[+] Verifying attack execution...")
    attack.verify_injection(target_namespace="phantom-eval", pod_name="emailservice")
    
    print("\n=========================================================")
    print("Attack injected successfully!")
    print("You can now inspect the cluster and view the drift events.")
    print("Run `python run_demo.py recover` to rollback the attack.")
    print("=========================================================")

def recover_solarwinds_attack():
    print("=========================================================")
    print("Recovering from SolarWinds-style Attack")
    print("=========================================================")
    attack = SolarWindsStyleAttack()
    attack.recover(target_namespace="phantom-eval", pod_name="emailservice")
    print("\n[+] Recovery complete.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "recover":
        recover_solarwinds_attack()
    else:
        run_solarwinds_attack()
