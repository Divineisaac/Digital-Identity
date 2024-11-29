# Identity Smart Contract

## Overview

This Clarity smart contract provides a comprehensive digital identity management system on the Stacks blockchain. It offers robust features for identity registration, profile management, attribute verification, delegation, and recovery mechanisms.

## Features

### 1. Identity Registration
- Users can register a unique digital identity
- Each identity includes:
  - Display name
  - Registration timestamp
  - Backup address
  - Identity score
  - Verification level

### 2. Profile Management
- Update display name
- Set and manage personal attributes
- Track identity modification history

### 3. Attribute Verification
- Add verifiable attributes to identity
- Allow trusted authorities to verify attributes
- Attributes include:
  - Verification status
  - Verification authority
  - Verification timestamp
  - Verification expiry

### 4. Identity Delegation
- Grant specific permissions to delegate addresses
- Flexible delegation with:
  - Granular permission control
  - Delegation duration
  - Sub-delegation capabilities
- Easy delegation management (add/remove)

### 5. Security and Recovery
- Activity logging for all identity-related actions
- Backup address for identity recovery
- Unauthorized access prevention
- Identity score tracking

## Error Handling

The contract includes comprehensive error codes for various scenarios:
- Unauthorized access
- Identity not found
- Attribute verification failures
- Delegate management errors

## Key Functions

### Registration
- `register-new-identity`: Create a new digital identity
- `update-display-name`: Modify identity display name

### Attributes
- `set-identity-attribute`: Add new attributes
- `verify-identity-attribute`: Verify attributes by authorized parties

### Delegation
- `add-identity-delegate`: Grant delegation permissions
- `remove-identity-delegate`: Revoke delegation
- `is-delegate-authorized`: Check delegation permissions

### Recovery
- `set-backup-address`: Set a recovery address for the identity

## Read-Only Functions

- `get-user-identity`: Retrieve identity details
- `get-identity-attribute`: Fetch specific attributes
- `get-identity-delegate`: Check delegate information
- `is-identity-registered`: Verify identity existence
- `get-identity-score`: Check identity reputation score

## Usage Example

```clarity
;; Register a new identity
(contract-call? .identity-contract register-new-identity "JohnDoe")

;; Add an attribute
(contract-call? .identity-contract set-identity-attribute "email" "john@example.com")

;; Verify an attribute
(contract-call? .identity-contract verify-identity-attribute user-principal "email")

;; Add a delegate
(contract-call? .identity-contract add-identity-delegate delegate-address 
    (list "profile-read" "attribute-update") 
    u86400 ;; 24-hour delegation 
    true   ;; allow sub-delegation
    "Temporary access"
)
```

## Security Considerations

- Only registered identities can perform most actions
- Verifiable attributes have expiration mechanisms
- Delegation has time-limited and permission-based access
- Activity logging for audit trails

## Limitations and Constraints

- Maximum attribute length: 256 characters
- Maximum delegate permissions: 10
- Verification timeout: 48 hours
- Identity score is incrementally updated