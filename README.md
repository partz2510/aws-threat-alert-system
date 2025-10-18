# 🚨 AWS Serverless Threat-Alert System

A lightweight, **event-driven security monitor** that automatically detects **failed AWS Console logins** via **CloudTrail**, analyzes them with **Lambda**, and sends instant **email alerts** through **SNS** — all built entirely on **serverless AWS services**.

---

## 🧩 Architecture

CloudTrail → S3 → Lambda → SNS → Email

python
Copy code

**Flow Explanation:**
1. **AWS CloudTrail** captures all console login activity.
2. **Amazon S3** stores the CloudTrail logs.
3. **AWS Lambda** is triggered whenever a new log file arrives.
4. Lambda scans the log for any `ConsoleLogin` events with `"Failure"`.
5. If detected, **Amazon SNS** sends an email alert to the administrator.

---

## 🛠️ AWS Services Used
| Service | Purpose |
|----------|----------|
| **AWS CloudTrail** | Records management and login events |
| **Amazon S3** | Stores CloudTrail log files |
| **AWS Lambda (Python 3.12)** | Processes new log files automatically |
| **Amazon SNS** | Sends real-time email notifications |
| **AWS IAM** | Manages secure roles and permissions |

---

## ⚙️ Step-by-Step Setup

### 1️⃣ Create S3 Bucket
- Name: `threat-alert-logs`
- Enable Versioning ✅  
- Enable Default Encryption (SSE-S3) ✅  
- Keep Public Access Blocked ✅  

### 2️⃣ Enable CloudTrail
- Trail name: `Threat-Alert-Trail`
- Use existing S3 bucket: `threat-alert-logs`
- Event type: **Management events** (Read + Write)
- Disable CloudWatch / Data / Insight events  

### 3️⃣ Create SNS Topic
- Topic name: `login-alert-topic`
- Protocol: **Email**
- Confirm subscription via email link  

### 4️⃣ Create IAM Role
Attach these managed policies:
- `AmazonS3ReadOnlyAccess`
- `AmazonSNSFullAccess`
- `CloudWatchLogsFullAccess`
Role name: **`lambda-threat-alert-role`**

### 5️⃣ Create Lambda Function
- Name: `threatAlertLambda`
- Runtime: Python 3.12
- Existing Role: `lambda-threat-alert-role`
- Paste the following code:

```python
import json, gzip, boto3
from io import BytesIO

sns = boto3.client('sns')
TOPIC_ARN = 'arn:aws:sns:ap-southeast-2:YOUR_ACCOUNT_ID:login-alert-topic'

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    obj = s3.get_object(Bucket=bucket, Key=key)
    bytestream = BytesIO(obj['Body'].read())
    with gzip.GzipFile(None, 'rb', fileobj=bytestream) as f:
        data = json.loads(f.read())

    alerts = []
    for record in data.get('Records', []):
        if record['eventName'] == 'ConsoleLogin':
            result = record.get('responseElements', {}).get('ConsoleLogin')
            if result == 'Failure':
                ip = record.get('sourceIPAddress', 'Unknown IP')
                user = record.get('userIdentity', {}).get('userName', 'Unknown User')
                alerts.append(f"🚨 Failed console login for user {user} from {ip}")

    if alerts:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject="AWS Threat Alert 🚨",
            Message="\n".join(alerts)
        )
        print("ALERT SENT:", alerts)
    else:
        print("No failed logins detected.")

    return {"statusCode": 200, "body": "Processed successfully"}
```



### 6️⃣ Add S3 Trigger
Trigger type: S3

Bucket: threat-alert-logs

Event type: All object create events

Enable trigger ✅

🧪 Testing the System
Wait 10–15 min for CloudTrail to start logging.

Attempt to sign in with an incorrect password to your IAM account.

CloudTrail logs the failure → S3 uploads → Lambda triggers → SNS sends an alert.

✅ Receive an email titled “AWS Threat Alert 🚨” similar to:

```
🚨 Failed console login for user partz2510-admin from 43.230.96.222
```


### 📸 Screenshots
Stage	Description
1	S3 bucket setup
2	CloudTrail trail summary
3	SNS topic confirmed
4	IAM role with attached policies
5	Lambda function summary
6	Trigger connection diagram
7	Alert email received

(All screenshots included in the /screenshots folder.)

### 💰 Cost Estimation
All services stay within the AWS Free Tier.
Approximate monthly cost: <$1 USD.

### 🚀 Future Enhancements
Add GeoIP lookup for login origins

Log alerts into DynamoDB

Create a QuickSight dashboard for visual analytics

Integrate Amazon GuardDuty findings

### 🧠 Learning Outcomes
Event-driven architecture design

Serverless automation

Practical IAM + SNS + Lambda integration

Real-world security monitoring pipeline

### 👤 Author
Parthiban Ganesan
AWS / Azure / Cybersecurity Projects Portfolio
🔗 GitHub: github.com/partz2510

