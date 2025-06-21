import boto3
import json
import os
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import base64
import zipfile
from pathlib import Path
import tempfile

logger = logging.getLogger(__name__)


@dataclass
class AWSConfig:
    """AWS configuration for SHIELD deployment."""
    region: str = "us-east-1"
    profile: Optional[str] = None
    lambda_function_name: str = "shield-security-api"
    ecs_cluster_name: str = "shield-cluster"
    ecr_repository: str = "shield/security-api"
    cloudwatch_log_group: str = "/aws/shield/security"
    s3_bucket: str = "shield-security-models"
    api_gateway_name: str = "shield-api"


class AWSDeployer:
    """AWS cloud deployment manager for SHIELD."""
    
    def __init__(self, config: Optional[AWSConfig] = None):
        self.config = config or AWSConfig()
        self.session = boto3.Session(
            profile_name=self.config.profile,
            region_name=self.config.region
        )
        
        # Initialize AWS clients
        self.lambda_client = self.session.client('lambda')
        self.ecs_client = self.session.client('ecs')
        self.ecr_client = self.session.client('ecr')
        self.s3_client = self.session.client('s3')
        self.cloudwatch_client = self.session.client('cloudwatch')
        self.logs_client = self.session.client('logs')
        self.apigateway_client = self.session.client('apigateway')
        self.iam_client = self.session.client('iam')
        
    def deploy_lambda_function(self, code_path: str = None) -> Dict[str, Any]:
        """Deploy SHIELD as AWS Lambda function."""
        try:
            # Create deployment package
            if not code_path:
                code_path = self._create_lambda_package()
            
            # Create or update Lambda function
            function_code = self._read_lambda_code(code_path)
            
            try:
                # Try to update existing function
                response = self.lambda_client.update_function_code(
                    FunctionName=self.config.lambda_function_name,
                    ZipFile=function_code
                )
                logger.info(f"Updated Lambda function: {self.config.lambda_function_name}")
                
            except self.lambda_client.exceptions.ResourceNotFoundException:
                # Create new function
                response = self.lambda_client.create_function(
                    FunctionName=self.config.lambda_function_name,
                    Runtime='python3.9',
                    Role=self._get_or_create_lambda_role(),
                    Handler='lambda_handler.handler',
                    Code={'ZipFile': function_code},
                    Description='SHIELD LLM Security API',
                    Timeout=30,
                    MemorySize=512,
                    Environment={
                        'Variables': {
                            'SHIELD_CONFIG': 'production',
                            'LOG_LEVEL': 'INFO'
                        }
                    },
                    Tags={
                        'Project': 'SHIELD',
                        'Environment': 'production'
                    }
                )
                logger.info(f"Created Lambda function: {self.config.lambda_function_name}")
            
            # Configure CloudWatch logging
            self._setup_cloudwatch_logging()
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to deploy Lambda function: {e}")
            raise
    
    def _create_lambda_package(self) -> str:
        """Create Lambda deployment package."""
        import tempfile
        import shutil
        
        with tempfile.TemporaryDirectory() as temp_dir:
            package_dir = Path(temp_dir) / "package"
            package_dir.mkdir()
            
            # Copy SHIELD source code
            shield_source = Path(__file__).parent.parent
            shutil.copytree(shield_source, package_dir / "shield")
            
            # Create Lambda handler
            handler_code = '''
import json
import sys
import os
sys.path.append('/opt/python')
sys.path.append('.')

from shield.api.shield_api import ShieldAPI
from shield.core.detector import SecurityDetector

# Initialize SHIELD components
detector = SecurityDetector()
api = ShieldAPI()

def handler(event, context):
    """AWS Lambda handler for SHIELD API."""
    try:
        # Parse request
        if 'body' in event:
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event
        
        # Process security request
        if event.get('httpMethod') == 'POST':
            if event.get('path') == '/api/v1/protect/input':
                result = detector.detect_threats(body.get('text', ''))
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'is_safe': not result['is_threat'],
                        'risk_score': result['confidence'],
                        'threats': result.get('threats', [])
                    })
                }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'status': 'SHIELD Lambda active'})
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': str(e)})
        }
'''
            
            with open(package_dir / "lambda_handler.py", 'w') as f:
                f.write(handler_code)
            
            # Create requirements.txt
            requirements = [
                'torch>=1.9.0',
                'transformers>=4.20.0',
                'scikit-learn>=1.0.0',
                'numpy>=1.21.0',
                'fastapi>=0.95.0',
                'pydantic>=1.10.0'
            ]
            
            with open(package_dir / "requirements.txt", 'w') as f:
                f.write('\n'.join(requirements))
            
            # Create zip file
            zip_path = temp_dir + "/shield-lambda.zip"
            shutil.make_archive(zip_path.replace('.zip', ''), 'zip', package_dir)
            
            return zip_path
    
    def _read_lambda_code(self, zip_path: str) -> bytes:
        """Read Lambda deployment package."""
        with open(zip_path, 'rb') as f:
            return f.read()
    
    def _get_or_create_lambda_role(self) -> str:
        """Get or create IAM role for Lambda function."""
        role_name = f"{self.config.lambda_function_name}-role"
        
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response['Role']['Arn']
            
        except self.iam_client.exceptions.NoSuchEntityException:
            # Create role
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            response = self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Role for SHIELD Lambda function"
            )
            
            # Attach basic Lambda execution policy
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
            
            return response['Role']['Arn']
    
    def deploy_ecs_service(self, docker_image: str) -> Dict[str, Any]:
        """Deploy SHIELD as ECS service."""
        try:
            # Create or update ECS cluster
            cluster_response = self._ensure_ecs_cluster()
            
            # Create task definition
            task_def_response = self._create_task_definition(docker_image)
            
            # Create or update service
            service_response = self._create_or_update_service(
                task_def_response['taskDefinition']['taskDefinitionArn']
            )
            
            logger.info(f"Deployed ECS service: {self.config.ecs_cluster_name}")
            return service_response
            
        except Exception as e:
            logger.error(f"Failed to deploy ECS service: {e}")
            raise
    
    def _ensure_ecs_cluster(self) -> Dict[str, Any]:
        """Ensure ECS cluster exists."""
        try:
            response = self.ecs_client.describe_clusters(
                clusters=[self.config.ecs_cluster_name]
            )
            
            if not response['clusters'] or response['clusters'][0]['status'] != 'ACTIVE':
                # Create cluster
                response = self.ecs_client.create_cluster(
                    clusterName=self.config.ecs_cluster_name,
                    tags=[
                        {'key': 'Project', 'value': 'SHIELD'},
                        {'key': 'Environment', 'value': 'production'}
                    ]
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to ensure ECS cluster: {e}")
            raise
    
    def _create_task_definition(self, docker_image: str) -> Dict[str, Any]:
        """Create ECS task definition."""
        task_definition = {
            'family': 'shield-security-api',
            'networkMode': 'awsvpc',
            'requiresCompatibilities': ['FARGATE'],
            'cpu': '512',
            'memory': '1024',
            'executionRoleArn': self._get_or_create_ecs_execution_role(),
            'containerDefinitions': [
                {
                    'name': 'shield-api',
                    'image': docker_image,
                    'portMappings': [
                        {
                            'containerPort': 8000,
                            'protocol': 'tcp'
                        }
                    ],
                    'essential': True,
                    'logConfiguration': {
                        'logDriver': 'awslogs',
                        'options': {
                            'awslogs-group': self.config.cloudwatch_log_group,
                            'awslogs-region': self.config.region,
                            'awslogs-stream-prefix': 'ecs'
                        }
                    },
                    'environment': [
                        {'name': 'SHIELD_CONFIG', 'value': 'production'},
                        {'name': 'LOG_LEVEL', 'value': 'INFO'}
                    ]
                }
            ]
        }
        
        return self.ecs_client.register_task_definition(**task_definition)
    
    def _create_or_update_service(self, task_definition_arn: str) -> Dict[str, Any]:
        """Create or update ECS service."""
        service_name = 'shield-api-service'
        
        try:
            # Try to update existing service
            response = self.ecs_client.update_service(
                cluster=self.config.ecs_cluster_name,
                service=service_name,
                taskDefinition=task_definition_arn,
                desiredCount=2
            )
            
        except self.ecs_client.exceptions.ServiceNotFoundException:
            # Create new service
            response = self.ecs_client.create_service(
                cluster=self.config.ecs_cluster_name,
                serviceName=service_name,
                taskDefinition=task_definition_arn,
                desiredCount=2,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': self._get_default_subnets(),
                        'securityGroups': [self._get_or_create_security_group()],
                        'assignPublicIp': 'ENABLED'
                    }
                },
                tags=[
                    {'key': 'Project', 'value': 'SHIELD'},
                    {'key': 'Environment', 'value': 'production'}
                ]
            )
        
        return response
    
    def _get_or_create_ecs_execution_role(self) -> str:
        """Get or create ECS execution role."""
        role_name = "shield-ecs-execution-role"
        
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response['Role']['Arn']
            
        except self.iam_client.exceptions.NoSuchEntityException:
            # Create role
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            response = self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            
            # Attach ECS task execution policy
            self.iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
            )
            
            return response['Role']['Arn']
    
    def setup_model_storage(self) -> Dict[str, Any]:
        """Setup S3 bucket for model storage."""
        try:
            # Create S3 bucket
            try:
                self.s3_client.create_bucket(Bucket=self.config.s3_bucket)
            except self.s3_client.exceptions.BucketAlreadyOwnedByYou:
                pass  # Bucket already exists
            
            # Configure bucket versioning
            self.s3_client.put_bucket_versioning(
                Bucket=self.config.s3_bucket,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Configure bucket encryption
            self.s3_client.put_bucket_encryption(
                Bucket=self.config.s3_bucket,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
            
            logger.info(f"Setup S3 bucket: {self.config.s3_bucket}")
            return {'bucket': self.config.s3_bucket, 'status': 'configured'}
            
        except Exception as e:
            logger.error(f"Failed to setup model storage: {e}")
            raise
    
    def upload_models(self, models_dir: str) -> List[str]:
        """Upload models to S3."""
        uploaded_models = []
        
        try:
            models_path = Path(models_dir)
            for model_file in models_path.rglob("*"):
                if model_file.is_file():
                    key = f"models/{model_file.relative_to(models_path)}"
                    
                    self.s3_client.upload_file(
                        str(model_file),
                        self.config.s3_bucket,
                        key
                    )
                    
                    uploaded_models.append(key)
                    logger.info(f"Uploaded model: {key}")
            
            return uploaded_models
            
        except Exception as e:
            logger.error(f"Failed to upload models: {e}")
            raise
    
    def _setup_cloudwatch_logging(self):
        """Setup CloudWatch logging."""
        try:
            self.logs_client.create_log_group(
                logGroupName=self.config.cloudwatch_log_group
            )
        except self.logs_client.exceptions.ResourceAlreadyExistsException:
            pass  # Log group already exists
    
    def _get_default_subnets(self) -> List[str]:
        """Get default VPC subnets."""
        ec2_client = self.session.client('ec2')
        
        # Get default VPC
        vpcs = ec2_client.describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}]
        )
        
        if not vpcs['Vpcs']:
            raise Exception("No default VPC found")
        
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        
        # Get subnets
        subnets = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        
        return [subnet['SubnetId'] for subnet in subnets['Subnets']]
    
    def _get_or_create_security_group(self) -> str:
        """Get or create security group for ECS."""
        ec2_client = self.session.client('ec2')
        group_name = 'shield-ecs-sg'
        
        try:
            # Try to find existing security group
            groups = ec2_client.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [group_name]}]
            )
            
            if groups['SecurityGroups']:
                return groups['SecurityGroups'][0]['GroupId']
            
            # Create new security group
            vpcs = ec2_client.describe_vpcs(
                Filters=[{'Name': 'isDefault', 'Values': ['true']}]
            )
            vpc_id = vpcs['Vpcs'][0]['VpcId']
            
            response = ec2_client.create_security_group(
                GroupName=group_name,
                Description='Security group for SHIELD ECS service',
                VpcId=vpc_id
            )
            
            group_id = response['GroupId']
            
            # Add inbound rule for HTTP traffic
            ec2_client.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 8000,
                        'ToPort': 8000,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            
            return group_id
            
        except Exception as e:
            logger.error(f"Failed to create security group: {e}")
            raise
    
    def get_deployment_status(self) -> Dict[str, Any]:
        """Get status of AWS deployments."""
        status = {
            'lambda': {'deployed': False, 'status': 'unknown'},
            'ecs': {'deployed': False, 'status': 'unknown'},
            's3': {'configured': False, 'models_count': 0},
            'cloudwatch': {'log_group_exists': False}
        }
        
        # Check Lambda function
        try:
            response = self.lambda_client.get_function(
                FunctionName=self.config.lambda_function_name
            )
            status['lambda'] = {
                'deployed': True,
                'status': response['Configuration']['State'],
                'last_modified': response['Configuration']['LastModified']
            }
        except self.lambda_client.exceptions.ResourceNotFoundException:
            pass
        
        # Check ECS service
        try:
            response = self.ecs_client.describe_services(
                cluster=self.config.ecs_cluster_name,
                services=['shield-api-service']
            )
            if response['services']:
                service = response['services'][0]
                status['ecs'] = {
                    'deployed': True,
                    'status': service['status'],
                    'running_count': service['runningCount'],
                    'desired_count': service['desiredCount']
                }
        except Exception:
            pass
        
        # Check S3 bucket
        try:
            self.s3_client.head_bucket(Bucket=self.config.s3_bucket)
            objects = self.s3_client.list_objects_v2(
                Bucket=self.config.s3_bucket,
                Prefix='models/'
            )
            status['s3'] = {
                'configured': True,
                'models_count': objects.get('KeyCount', 0)
            }
        except Exception:
            pass
        
        # Check CloudWatch log group
        try:
            self.logs_client.describe_log_groups(
                logGroupNamePrefix=self.config.cloudwatch_log_group
            )
            status['cloudwatch']['log_group_exists'] = True
        except Exception:
            pass
        
        return status
    
    def cleanup_deployment(self):
        """Clean up AWS resources."""
        logger.info("Starting AWS resource cleanup...")
        
        # Delete Lambda function
        try:
            self.lambda_client.delete_function(
                FunctionName=self.config.lambda_function_name
            )
            logger.info("Deleted Lambda function")
        except Exception as e:
            logger.warning(f"Failed to delete Lambda function: {e}")
        
        # Delete ECS service
        try:
            self.ecs_client.update_service(
                cluster=self.config.ecs_cluster_name,
                service='shield-api-service',
                desiredCount=0
            )
            self.ecs_client.delete_service(
                cluster=self.config.ecs_cluster_name,
                service='shield-api-service'
            )
            logger.info("Deleted ECS service")
        except Exception as e:
            logger.warning(f"Failed to delete ECS service: {e}")
        
        logger.info("AWS cleanup completed") 