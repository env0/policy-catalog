# env0 Policy Catalog

This repository contains a catalog of reusable **OPA/Rego policies** for use with env0.  
Each policy is defined in its own folder and includes the policy logic, metadata, and configuration schema.  

The goal is to provide real-world, ready-to-use examples for cost, security, compliance, and other categories, while keeping the structure consistent and easy to extend.

---

## Repository Structure

Each folder in this repository represents a single policy template.  
A policy folder must include the following files:

### 1. `policy.rego`
The OPA/Rego policy implementation.  
This file contains the actual rules that enforce the desired behavior.

### 2. `metadata.yml`
A YAML file that contains metadata and optional configuration for the policy.

**Fields:**
- **name**: Friendly name of the policy template.
- **description**: Explanation of what the policy does.
- **categories** *(optional)*: Category of the policy (e.g., cost, security, compliance, best-practice).
- **tags** *(optional)*: Cloud resources or concepts targeted by the policy.
- **cloudProvider** *(optional)*: Relevant cloud provider (`aws`, `gcp`, `azure`). Leave blank for multi-cloud.
- **configurationSchema** *(optional)*: Schema describing configuration arguments for the policy.

**Example:**
```yaml
name: "Deny Public S3 Buckets"
description: "Ensures that S3 buckets are not publicly accessible."
categories:
  - "security"
tags:
  - "aws"
  - "s3"
  - "public-access"
cloudProvider: "aws"
```

### 3. `configurationSchema.json`
A JSON Schema that describes optional or required parameters to customize the policy.  
This allows policies to be flexible and accept input arguments.

**Schema Fields:**
- **$schema**: JSON Schema version.
- **title**: Human-readable name of the schema.
- **type**: Root object type (usually `object`).
- **properties**: Key-value map of supported parameters.
- **additionalProperties**: Defines whether extra fields are allowed (`true`/`false`).

**Example:**
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "S3 Bucket Public Access Configuration",
  "type": "object",
  "properties": {
    "allowExceptions": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "description": "List of bucket names exempted from the policy."
    }
  },
  "additionalProperties": false
}
```
