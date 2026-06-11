#!/usr/bin/env python3.11

import boto3
import argparse
import subprocess
import logging
from typing import Tuple, Optional, Dict, List, Any
from dataclasses import dataclass
from botocore.exceptions import ClientError, NoCredentialsError
import sys
from pathlib import Path
import json
from datetime import datetime
import os
import time
import concurrent.futures
import colorama
from colorama import Fore, Style

# Inicializar colorama para saída colorida em todos os sistemas
colorama.init(autoreset=True)

'''
AWS Cognito Credential Extractor and Tester
-------------------------------------------
- Fetches credentials for an identity pool.
- Tests AWS permissions for extracted credentials.
- Runs enumerate-iam.py for deeper analysis.
'''
VERSION=f"{Fore.WHITE}dev-v3.0{Fore.YELLOW}"

TITLE = f'''{Fore.YELLOW}
                    _
          {VERSION} | |
 _ __   ___   ___  | |
| '_ \ / _ \ / _ \ | |
| |A| | |W| | |S| || |
| |_| | |_| | |_| || |
| .__/ \___/ \___/ |_|
| |         ~~DIVER 🤿
|_|{Fore.WHITE} HOW DEEP CAN I GO?{Fore.CYAN}
⎼─–─⎼⎼─–─⎼⎼─–─⎼⎼─–─⎼⎼─–─⎼
⎽⎼–⎻⎺⎺⎻–⎼⎽⎽⎼–⎻⎺⎺⎻–⎼⎽⎽⎼
``'-.,_,.-'``'-.,_,.='
-.,_,.='``'-.,_,.-'``'
            {Fore.LIGHTBLUE_EX}@TheZakMan
{Style.RESET_ALL}'''



'''
[Example]:
./PoolDiver.py -r "us-east-1" -id "us-east-1:38779a26-c4f5-4a78-b620-ba6040dfae74"
./PoolDiver.py -r "us-east-1" -id "us-east-1:38779a26-c4f5-4a78-b620-ba6040dfae74" -t

aws cognito-identity get-id --identity-pool-id <IdentityPoolId> --region <Region>
aws cognito-identity get-credentials-for-identity --identity-id <IdentityId> --region <Region>
'''


@dataclass
class AWSCredentials:
    """Data class to store AWS credentials"""
    access_key: str
    secret_key: str
    session_token: str
    identity_id: str
    region: str
    expiration: datetime = None

    def is_expired(self) -> bool:
        """Check if credentials have expired"""
        if self.expiration is None:
            return False
        return datetime.now() > self.expiration

    def to_dict(self) -> Dict[str, str]:
        """Convert credentials to dictionary format"""
        return {
            "AccessKeyId": self.access_key,
            "SecretAccessKey": self.secret_key,
            "SessionToken": self.session_token,
            "IdentityId": self.identity_id,
            "Region": self.region,
            "Expiration": str(self.expiration) if self.expiration else None
        }

    def save_to_file(self, filepath: Path) -> None:
        """Save credentials to file for later use"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=4)


# change this path for your own enumerate-iam
# https://github.com/andresriancho/enumerate-iam

class PoolDiverConfig:
    """Configuration management class"""
    ENUMERATE_IAM_PATH = Path("/Users/thezakman/Toolz/enumerate-iam/")
    LOG_FILE = Path('pooldiver_output.log')
    OUTPUT_DIR = Path('pool_diver_results')
    CREDENTIALS_DIR = Path('credentials')
    MAX_WORKERS = 5  # Para processamento paralelo
    SERVICES_TO_TEST = [
        's3', 'ec2', 'lambda', 'dynamodb', 'iam', 'ssm',
        'secretsmanager', 'sqs', 'sns', 'rds', 'cognito-identity'
    ]

    @classmethod
    def setup(cls):
        """Setup necessary directories and configurations"""
        cls.OUTPUT_DIR.mkdir(exist_ok=True)
        cls.CREDENTIALS_DIR.mkdir(exist_ok=True)
        return cls

class PoolDiverLogger:
    """Handles logging configuration"""
    @staticmethod
    def setup():
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(PoolDiverConfig.LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger(__name__)

class AWSServiceTester:
    """Handles AWS service permission testing"""
    def __init__(self, session: boto3.Session, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.results = {}
        self.start_time = time.time()

    def test_all_services(self) -> None:
        """Test all configured services in parallel"""
        services_map = {
            's3': self.test_s3,
            'ec2': self.test_ec2,
            'lambda': self.test_lambda,
            'dynamodb': self.test_dynamodb,
            'iam': self.test_iam,
            'ssm': self.test_ssm,
            'secretsmanager': self.test_secretsmanager,
            'sqs': self.test_sqs,
            'sns': self.test_sns,
            'rds': self.test_rds
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=PoolDiverConfig.MAX_WORKERS) as executor:
            future_to_service = {
                executor.submit(self.test_service, service, func): service
                for service, func in services_map.items()
                if service in PoolDiverConfig.SERVICES_TO_TEST
            }

            for future in concurrent.futures.as_completed(future_to_service):
                service = future_to_service[future]
                try:
                    result = future.result()
                    if result.get("error"):
                        self.logger.info(f"{Fore.RED}✗ {service.upper()} test completed - Access Denied")
                    else:
                        self.logger.info(f"{Fore.GREEN}✓ {service.upper()} test completed - Access Granted")
                except Exception as e:
                    self.logger.error(f"{Fore.RED}✗ {service.upper()} test failed: {str(e)}")

    def test_dynamodb(self):
        dynamodb = self.session.client('dynamodb')
        tables = dynamodb.list_tables()
        return {
            "tables": tables.get("TableNames", [])
        }

    def test_iam(self):
        iam = self.session.client('iam')
        result = {}

        try:
            result["user"] = iam.get_user().get("User", {})
        except:
            result["user"] = "Failed to retrieve"

        try:
            result["roles"] = [r["RoleName"] for r in iam.list_roles().get("Roles", [])]
        except:
            result["roles"] = "Failed to retrieve"

        return result

    def test_ssm(self):
        ssm = self.session.client('ssm')
        parameters = ssm.describe_parameters()
        return {
            "parameters": [p["Name"] for p in parameters.get("Parameters", [])]
        }

    def test_secretsmanager(self):
        sm = self.session.client('secretsmanager')
        secrets = sm.list_secrets()
        return {
            "secrets": [s["Name"] for s in secrets.get("SecretList", [])]
        }

    def test_sqs(self):
        sqs = self.session.client('sqs')
        queues = sqs.list_queues()
        return {
            "queues": queues.get("QueueUrls", [])
        }

    def test_sns(self):
        sns = self.session.client('sns')
        topics = sns.list_topics()
        return {
            "topics": [t["TopicArn"] for t in topics.get("Topics", [])]
        }

    def test_rds(self):
        rds = self.session.client('rds')
        instances = rds.describe_db_instances()
        return {
            "instances": [
                {"id": i["DBInstanceIdentifier"], "engine": i["Engine"]}
                for i in instances.get("DBInstances", [])
            ]
        }

    def save_results(self):
        """Save test results to a JSON file with summary"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = PoolDiverConfig.OUTPUT_DIR / f"scan_results_{timestamp}.json"

        # Adicionar resumo e estatísticas
        accessible_services = sum(1 for s in self.results.values() if not s.get("error"))
        total_services = len(self.results)

        self.results["summary"] = {
            "tested_services": total_services,
            "accessible_services": accessible_services,
            "scan_duration": f"{time.time() - self.start_time:.2f}s",
            "timestamp": datetime.now().isoformat()
        }

        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        self.logger.info(f"{Fore.GREEN}✓ Results saved to {output_file}")

        # Criar relatório resumido em txt
        summary_file = PoolDiverConfig.OUTPUT_DIR / f"summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write("=== PoolDiver Scan Summary ===\n\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {time.time() - self.start_time:.2f} seconds\n")
            f.write(f"Services tested: {total_services}\n")
            f.write(f"Accessible services: {accessible_services}/{total_services} ({accessible_services/total_services*100 if total_services > 0 else 0:.1f}%)\n\n")

            f.write("Service Access Summary:\n")
            for service, result in self.results.items():
                if service == "summary":
                    continue
                if not result.get("error"):
                    status = "✓ ACCESSIBLE"
                    details = self._get_result_details(service, result)
                else:
                    status = f"✗ DENIED ({result.get('error')})"
                    details = ""
                f.write(f"- {service}: {status} {details}\n")

        self.logger.info(f"{Fore.GREEN}✓ Summary report saved to {summary_file}")

        # Exibir um resumo no console
        self.logger.info(f"\n{Fore.CYAN}=== Scan Complete ===")
        self.logger.info(f"{Fore.CYAN}Duration: {time.time() - self.start_time:.2f} seconds")
        if accessible_services > 0:
            self.logger.info(f"{Fore.GREEN}✓ Accessible services: {accessible_services}/{total_services}")
        else:
            self.logger.info(f"{Fore.RED}✗ No accessible services found")

    def _get_result_details(self, service, result):
        """Get summary details for successful service tests"""
        if service == 's3' and 'buckets' in result:
            bucket_count = len(result['buckets'])
            return f"({bucket_count} bucket{'s' if bucket_count != 1 else ''})"
        elif service == 'ec2' and 'instances' in result:
            instance_count = len(result['instances'])
            return f"({instance_count} instance{'s' if instance_count != 1 else ''})"
        elif service == 'lambda' and 'functions' in result:
            function_count = len(result['functions'])
            return f"({function_count} function{'s' if function_count != 1 else ''})"
        return ""

    def test_service(self, service_name: str, test_function) -> dict:
        """Test permissions for a specific AWS service"""
        self.logger.info(f"{Fore.BLUE}Testing {service_name} permissions...")
        try:
            result = test_function()
            self.results[service_name] = result
            return result
        except ClientError as e:
            error_code = e.response['Error']['Code']
            self.results[service_name] = {"error": error_code}
            self.logger.warning(f"{Fore.YELLOW}⚠ {service_name} test failed: {error_code}")
            return {"error": error_code}
        except Exception as e:
            self.logger.error(f"{Fore.RED}✗ Unexpected error testing {service_name}: {str(e)}")
            self.results[service_name] = {"error": str(e)}
            return {"error": str(e)}

    def test_s3(self):
        s3 = self.session.client('s3')
        buckets = s3.list_buckets()
        return {
            "buckets": [{"name": b["Name"], "creation_date": str(b["CreationDate"])}
                       for b in buckets.get("Buckets", [])]
        }

    def test_ec2(self):
        ec2 = self.session.client('ec2')
        instances = ec2.describe_instances()
        return {
            "instances": [
                {
                    "id": i["InstanceId"],
                    "type": i["InstanceType"],
                    "state": i["State"]["Name"],
                    "vpc_id": i.get("VpcId", "N/A")
                }
                for r in instances.get("Reservations", [])
                for i in r.get("Instances", [])
            ]
        }

    def test_lambda(self):
        lambda_client = self.session.client('lambda')
        functions = lambda_client.list_functions()
        return {
            "functions": [
                {
                    "name": f["FunctionName"],
                    "runtime": f["Runtime"],
                    "handler": f["Handler"]
                }
                for f in functions.get("Functions", [])
            ]
        }

class PoolDiver:
    """Main class for AWS Cognito credential testing"""
    def __init__(self):
        self.config = PoolDiverConfig.setup()
        self.logger = PoolDiverLogger.setup()

    def get_pool_credentials(self, region: str, identity_pool: str) -> AWSCredentials:
        """Fetch AWS credentials for a Cognito identity pool"""
        try:
            self.logger.info(f"{Fore.BLUE}Fetching credentials for pool: {identity_pool} in {region}")
            client = boto3.client('cognito-identity', region_name=region)

            identity_response = client.get_id(IdentityPoolId=identity_pool)
            identity_id = identity_response['IdentityId']
            self.logger.info(f"{Fore.GREEN}Identity obtained: {identity_id}")

            creds_response = client.get_credentials_for_identity(IdentityId=identity_id)
            credentials = creds_response['Credentials']

            creds = AWSCredentials(
                access_key=credentials['AccessKeyId'],
                secret_key=credentials['SecretKey'],
                session_token=credentials['SessionToken'],
                identity_id=identity_id,
                region=region,
                expiration=credentials.get('Expiration')
            )

            # Salvar credenciais
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            cred_file = self.config.CREDENTIALS_DIR / f"credentials_{identity_id.replace(':', '_')}_{timestamp}.json"
            creds.save_to_file(cred_file)
            self.logger.info(f"{Fore.GREEN}Credentials saved to {cred_file}")

            return creds
        except NoCredentialsError:
            self.logger.error(f"{Fore.RED}No credentials found")
            raise
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to fetch credentials: {str(e)}")
            raise

    def run(self, args: argparse.Namespace):
        """Main execution flow"""
        try:
            print(TITLE)
            self.logger.info(f"{Fore.CYAN}PoolDiver v2.0 starting...")

            # Get credentials
            credentials = self.get_pool_credentials(args.region, args.identity)
            self.logger.info(f"{Fore.GREEN}✓ Successfully obtained credentials for identity: {credentials.identity_id}")

            # Create AWS session
            session = boto3.Session(
                aws_access_key_id=credentials.access_key,
                aws_secret_access_key=credentials.secret_key,
                aws_session_token=credentials.session_token,
                region_name=credentials.region
            )

            # Verificar identidade
            self.logger.info(f"{Fore.BLUE}Checking AWS identity...")
            try:
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                self.logger.info(f"{Fore.GREEN}✓ Authenticated as: {identity['Arn']}")
            except Exception as e:
                self.logger.warning(f"{Fore.YELLOW}⚠ Could not determine identity: {str(e)}")

            # Run tests if requested
            if args.test:
                self.logger.info(f"{Fore.BLUE}Starting AWS service tests...")
                tester = AWSServiceTester(session, self.logger)
                tester.test_all_services()
                tester.save_results()

                # Run enumerate-iam if path exists
                if self.config.ENUMERATE_IAM_PATH.exists() and not args.no_enumerate:
                    enumerate_output_file = self.run_enumerate_iam(credentials)
                    if enumerate_output_file:
                        self.combine_scan_results(tester.results, enumerate_output_file)
                else:
                    if args.no_enumerate:
                        self.logger.warning(f"{Fore.YELLOW}⚠ enumerate-iam skipped by user request")
                    else:
                        self.logger.warning(f"{Fore.YELLOW}⚠ enumerate-iam path not found, skipping...")

            self.logger.info(f"{Fore.GREEN}✓ PoolDiver execution completed successfully")

        except Exception as e:
            self.logger.error(f"{Fore.RED}✗ Error during execution: {str(e)}")
            raise

    def run_enumerate_iam(self, credentials: AWSCredentials):
        """Run the enumerate-iam script with live output"""
        try:
            self.logger.info(f"{Fore.BLUE}Running enumerate-iam...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.config.OUTPUT_DIR / f"enumerate_iam_output_{timestamp}.txt"

            # Usar processo simples sem captura de saída para garantir exibição em tempo real
            env = os.environ.copy()
            env["AWS_ACCESS_KEY_ID"] = credentials.access_key
            env["AWS_SECRET_ACCESS_KEY"] = credentials.secret_key
            env["AWS_SESSION_TOKEN"] = credentials.session_token
            env["AWS_DEFAULT_REGION"] = credentials.region

            print(f"{Fore.CYAN}======== enumerate-iam Output ========{Style.RESET_ALL}")

            # Usar o subprocess.run que é mais simples e mostra a saída em tempo real
            with open(output_file, 'w') as f:
                # Redirecionar saída para tee para escrever tanto no arquivo quanto no stdout
                try:
                    cmd = [
                        "python3.11",
                        str(self.config.ENUMERATE_IAM_PATH / "enumerate-iam.py"),
                        "--access-key", credentials.access_key,
                        "--secret-key", credentials.secret_key,
                        "--region", credentials.region,
                        "--session-token", credentials.session_token
                    ]

                    # Usar o tee do sistema para dividir a saída para arquivo e terminal
                    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                    # Ler e processar a saída linha por linha
                    while True:
                        line = proc.stdout.readline()
                        if not line and proc.poll() is not None:
                            break

                        if line:
                            # Decodificar a linha
                            try:
                                line_text = line.decode('utf-8').rstrip()
                            except UnicodeDecodeError:
                                line_text = line.decode('latin-1').rstrip()

                            # Colorir baseado no conteúdo
                            if "ERROR" in line_text or "DENIED" in line_text or "failed" in line_text:
                                print(f"{Fore.RED}{line_text}{Style.RESET_ALL}")
                            elif "SUCCESS" in line_text or "ALLOWED" in line_text or "completed" in line_text:
                                print(f"{Fore.GREEN}{line_text}{Style.RESET_ALL}")
                            elif "WARNING" in line_text:
                                print(f"{Fore.YELLOW}{line_text}{Style.RESET_ALL}")
                            else:
                                print(line_text)

                            # Escrever no arquivo
                            f.write(line_text + "\n")
                            f.flush()  # Garantir que o texto seja escrito imediatamente

                    # Obter o código de retorno
                    return_code = proc.poll()

                    print(f"{Fore.CYAN}======== End of enumerate-iam Output ========{Style.RESET_ALL}")

                    if return_code != 0:
                        self.logger.error(f"{Fore.RED}✗ enumerate-iam failed with return code {return_code}")
                    else:
                        self.logger.info(f"{Fore.GREEN}✓ enumerate-iam completed successfully")
                        self.logger.info(f"{Fore.GREEN}✓ Output saved to {output_file}")
                        return output_file

                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}⚠ Process interrupted by user{Style.RESET_ALL}")
                    f.write("\n\n=== Process interrupted by user ===\n")
                    raise

        except KeyboardInterrupt:
            self.logger.warning(f"{Fore.YELLOW}⚠ enumerate-iam process interrupted by user")
            # Tente encerrar o processo se ele ainda estiver em execução
            try:
                if 'proc' in locals() and proc.poll() is None:
                    proc.terminate()
                    self.logger.info(f"{Fore.YELLOW}Terminated enumerate-iam process")
            except:
                pass
        except Exception as e:
            self.logger.error(f"{Fore.RED}✗ Failed to run enumerate-iam: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced AWS Cognito Credential Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3.11 PoolDiver.py -r "us-east-1" -id "us-east-1:38779a26-c4f5-4a78-b620-ba6040dfae74" -t
  python3.11 PoolDiver.py -r "us-east-1" -id "us-east-1:38779a26-c4f5-4a78-b620-ba6040dfae74" -t -s s3,ec2,lambda
'''
    )
    parser.add_argument('-t', '--test', action='store_true',
                       help='Run AWS service permission tests')
    parser.add_argument('-r', '--region', required=True,
                       help='AWS region')
    parser.add_argument('-id', '--identity', required=True,
                       help='Cognito Identity Pool ID')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('-s', '--services',
                       help='Comma-separated list of services to test (default: all)')
    parser.add_argument('--no-enumerate', action='store_true',
                       help='Skip running enumerate-iam')
    parser.add_argument('--output',
                       help='Custom output directory for results')

    args = parser.parse_args()

    # Process services list if provided
    if args.services:
        PoolDiverConfig.SERVICES_TO_TEST = args.services.split(',')

    # Process custom output directory
    if args.output:
        PoolDiverConfig.OUTPUT_DIR = Path(args.output)

    return args

if __name__ == "__main__":
    try:
        args = parse_arguments()
        pool_diver = PoolDiver()
        pool_diver.run(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)
