# NVD API to Supabase Lambda Function

This AWS Lambda function fetches vulnerability data from the National Vulnerability Database (NVD) API and upserts it to a Supabase database. It's designed to run on a schedule to keep vulnerability data up-to-date.

## Features

- **Comprehensive Data Fetching**: Retrieves vulnerabilities published in the last 365 days
- **Intelligent Chunking**: Processes data in 120-day chunks to comply with NVD API best practices
- **Rate Limiting**: Implements proper rate limiting to respect NVD API limits
- **Batch Processing**: Upserts data to Supabase in batches of 2000 records for optimal performance
- **Error Handling**: Robust error handling with retry logic and comprehensive logging
- **CVSS Score Extraction**: Prioritizes CVSS 3.1, falls back to 3.0, then 2.0
- **Production Ready**: Follows AWS Lambda best practices with proper logging and monitoring

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Lambda    │───▶│    NVD API      │    │   Supabase      │
│   (Scheduler)   │    │                 │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       ▲
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                        ┌─────────────────┐
                        │  CloudWatch     │
                        │  Logs           │
                        └─────────────────┘
```

## Prerequisites

### Supabase Setup

1. Create a Supabase project
2. Create the vulnerabilities table:

```sql
CREATE TABLE vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    published_date TIMESTAMPTZ,
    last_modified_date TIMESTAMPTZ,
    cvss_score DECIMAL(3,1),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_published_date ON vulnerabilities(published_date);
CREATE INDEX idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score);
```

### NVD API Key

1. Request an API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key)
2. API key is optional but highly recommended for better rate limits

## Environment Variables

The Lambda function requires the following environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_URL` | Your Supabase project URL | Yes |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key | Yes |
| `NVD_API_KEY` | NVD API key for higher rate limits | No |

## Deployment

### Option 1: Using AWS CLI

1. Create the deployment package:
```bash
python deployment_package.py
```

2. Create the Lambda function:
```bash
aws lambda create-function \
    --function-name nvd-vulnerability-sync \
    --runtime python3.9 \
    --role arn:aws:iam::YOUR_ACCOUNT:role/lambda-execution-role \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://nvd_lambda_function.zip \
    --timeout 900 \
    --memory-size 512
```

3. Set environment variables:
```bash
aws lambda update-function-configuration \
    --function-name nvd-vulnerability-sync \
    --environment Variables='{
        "SUPABASE_URL":"https://your-project.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY":"your-service-role-key",
        "NVD_API_KEY":"your-nvd-api-key"
    }'
```

### Option 2: Using AWS Console

1. Create deployment package: `python deployment_package.py`
2. Upload `nvd_lambda_function.zip` through AWS Console
3. Set environment variables in the Configuration tab
4. Configure timeout to 15 minutes and memory to 512MB

### Option 3: Using Terraform

```hcl
resource "aws_lambda_function" "nvd_sync" {
  filename         = "nvd_lambda_function.zip"
  function_name    = "nvd-vulnerability-sync"
  role            = aws_iam_role.lambda_role.arn
  handler         = "lambda_function.lambda_handler"
  runtime         = "python3.9"
  timeout         = 900
  memory_size     = 512

  environment {
    variables = {
      SUPABASE_URL              = var.supabase_url
      SUPABASE_SERVICE_ROLE_KEY = var.supabase_service_role_key
      NVD_API_KEY              = var.nvd_api_key
    }
  }
}
```

## Scheduling

Set up a CloudWatch Events rule to run the function on a schedule:

```bash
# Run daily at 2 AM UTC
aws events put-rule \
    --name nvd-sync-schedule \
    --schedule-expression "cron(0 2 * * ? *)"

aws lambda add-permission \
    --function-name nvd-vulnerability-sync \
    --statement-id nvd-sync-schedule \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn arn:aws:events:REGION:ACCOUNT:rule/nvd-sync-schedule

aws events put-targets \
    --rule nvd-sync-schedule \
    --targets "Id"="1","Arn"="arn:aws:lambda:REGION:ACCOUNT:function:nvd-vulnerability-sync"
```

## Testing

### Unit Tests

Run unit tests:
```bash
python -m pytest test_lambda_function.py -v
```

### Functional Tests

Run functional tests:
```bash
python -m pytest test_functional.py -v
```

### Integration Testing

Test with a small date range:
```bash
python -c "
import lambda_function
import json
from datetime import datetime, timedelta

# Set environment variables first
import os
os.environ['SUPABASE_URL'] = 'your-url'
os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'your-key'

# Test with small date range
event = {}
context = type('Context', (), {'aws_request_id': 'test'})()
result = lambda_function.lambda_handler(event, context)
print(json.dumps(result, indent=2))
"
```

## Monitoring

### CloudWatch Metrics

The function automatically logs to CloudWatch. Key metrics to monitor:

- **Duration**: Function execution time
- **Errors**: Number of failed executions
- **Invocations**: Number of function calls

### Custom Metrics

The function logs structured information:

```python
# Example log entries
INFO: Starting NVD vulnerability data sync
INFO: Fetching vulnerabilities from 2023-01-01 to 2023-12-31
INFO: Processing chunk: 2023-01-01 to 2023-05-01
INFO: Fetched 1500 vulnerabilities (total: 1500)
INFO: Successfully upserted batch of 1500 records
INFO: Successfully processed 15000 total vulnerabilities
```

### Alerts

Set up CloudWatch alarms for:

- Function errors
- Long execution times (>10 minutes)
- Memory usage spikes

## Performance Considerations

### Memory and Timeout

- **Memory**: 512MB recommended for processing large datasets
- **Timeout**: 15 minutes to handle full 365-day sync
- **Concurrent Executions**: Set to 1 to avoid rate limiting issues

### Cost Optimization

- **Scheduling**: Run daily rather than hourly to minimize costs
- **Memory**: Monitor actual usage and adjust if needed
- **API Key**: Use NVD API key to avoid rate limiting delays

### Rate Limiting

The function implements several rate limiting strategies:

- 6-second delay between API requests (NVD allows 10/minute)
- 30-second retry delay for rate-limited requests
- Exponential backoff for failed requests

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase Lambda timeout to 15 minutes
   - Check if NVD API is responding slowly

2. **Memory Errors**
   - Increase Lambda memory allocation
   - Check for memory leaks in processing

3. **Rate Limiting**
   - Ensure NVD API key is configured
   - Check CloudWatch logs for 429 responses

4. **Supabase Connection Errors**
   - Verify environment variables
   - Check Supabase service status
   - Ensure service role key has proper permissions

### Debug Mode

Enable debug logging by setting log level:

```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

### Manual Testing

Test individual components:

```python
# Test date chunking
from datetime import datetime, timedelta
import lambda_function

start_date = datetime.utcnow() - timedelta(days=365)
end_date = datetime.utcnow()
chunks = lambda_function.generate_date_chunks(start_date, end_date, 120)
print(f"Generated {len(chunks)} chunks")

# Test CVSS extraction
metrics = {
    'cvssMetricV31': [{'cvssData': {'baseScore': 7.5}}]
}
score = lambda_function.extract_cvss_score(metrics)
print(f"CVSS Score: {score}")
```

## Security Considerations

- **API Keys**: Store in environment variables, never in code
- **IAM Roles**: Use least-privilege principle
- **VPC**: Consider running in VPC for additional security
- **Encryption**: Enable encryption at rest for Lambda environment variables

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.