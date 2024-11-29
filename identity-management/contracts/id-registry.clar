;; Identity Smart Contract
;; Description: A comprehensive digital identity management system
;; Features: Identity registration, profile management, attribute verification,
;;          identity delegation, and recovery mechanisms

;; Constants for configuration
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MAX-ATTRIBUTE-LENGTH u256)
(define-constant MAX-DELEGATE-PERMISSIONS u10)
(define-constant VERIFICATION-TIMEOUT u2880) ;; 48 hours in blocks
(define-constant MAX-DELEGATION-DURATION u52560) ;; 1 year in blocks (assuming 10-minute block time)

;; Error codes with descriptive names
(define-constant ERR-UNAUTHORIZED-ACCESS (err u100))
(define-constant ERR-IDENTITY-EXISTS (err u101))
(define-constant ERR-IDENTITY-NOT-FOUND (err u102))
(define-constant ERR-ATTRIBUTE-NOT-FOUND (err u103))
(define-constant ERR-UNAUTHORIZED-VERIFIER (err u104))
(define-constant ERR-VERIFICATION-TIMEOUT (err u105))
(define-constant ERR-DELEGATE-NOT-FOUND (err u106))
(define-constant ERR-INVALID-LENGTH (err u107))
(define-constant ERR-SYSTEM-FAILURE (err u108))
(define-constant ERR-EXPIRED-DELEGATION (err u109))
(define-constant ERR-INVALID-INPUT (err u110))

;; Primary data structure for user identities
(define-map user-identities
  principal  ;; The user's blockchain address
  {
    identity-active: bool,            ;; Whether the identity is currently active
    display-name: (string-ascii 64),  ;; User's displayed name
    registration-timestamp: uint,      ;; When the identity was created
    last-modified-timestamp: uint,     ;; Last update timestamp
    backup-address: (optional principal), ;; Recovery address
    identity-score: uint,              ;; Reputation score
    verification-level: uint           ;; Level of identity verification (0-5)
  }
)

;; Stores verifiable attributes for each identity
(define-map identity-attributes
  {identity-owner: principal, attribute-name: (string-ascii 32)}
  {
    attribute-value: (string-ascii 256),
    is-verified: bool,
    verification-authority: (optional principal),
    verification-timestamp: (optional uint),
    verification-expiry: (optional uint),
    verification-metadata: (optional (string-ascii 256))
  }
)

;; Manages delegation relationships and permissions
(define-map identity-delegates
  {identity-owner: principal, delegate-address: principal}
  {
    granted-permissions: (list 10 (string-ascii 32)),
    delegation-expiry: uint,
    delegation-metadata: (string-ascii 256),
    can-sub-delegate: bool
  }
)

;; Activity tracking for security
(define-map identity-activity-log
  {identity-owner: principal, activity-timestamp: uint}
  {
    activity-type: (string-ascii 32),
    activity-data: (optional (string-ascii 64)),
    initiated-by: principal
  }
)

;; Read-only functions
(define-read-only (get-user-identity (user-address principal))
  (match (map-get? user-identities user-address)
    user-identity user-identity
    {
      identity-active: false,
      display-name: "",
      registration-timestamp: u0,
      last-modified-timestamp: u0,
      backup-address: none,
      identity-score: u0,
      verification-level: u0
    }
  )
)

(define-read-only (get-identity-attribute (identity-owner principal) (attribute-name (string-ascii 32)))
  (map-get? identity-attributes {identity-owner: identity-owner, attribute-name: attribute-name})
)

(define-read-only (get-identity-delegate (identity-owner principal) (delegate-address principal))
  (map-get? identity-delegates {identity-owner: identity-owner, delegate-address: delegate-address})
)

(define-read-only (is-identity-registered (user-address principal))
  (match (map-get? user-identities user-address)
    user-identity (get identity-active user-identity)
    false
  )
)

(define-read-only (get-identity-score (user-address principal))
  (match (map-get? user-identities user-address)
    user-identity (get identity-score user-identity)
    u0
  )
)

;; Input validation functions
(define-private (is-valid-string (input (string-ascii 256)))
  (and 
    (>= (len input) u1)
    (<= (len input) u256)
  )
)

(define-private (is-valid-permission-list (permissions (list 10 (string-ascii 32))))
  (and
    (>= (len permissions) u1)
    (<= (len permissions) MAX-DELEGATE-PERMISSIONS)
    (is-eq (len permissions) (len (filter is-valid-string permissions)))
  )
)

(define-private (is-valid-delegation-duration (duration uint))
  (<= duration MAX-DELEGATION-DURATION)
)

;; Public functions
(define-public (register-new-identity (display-name (string-ascii 64)))
  (let
    (
      (user-principal tx-sender)
      (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
    )
    (asserts! (not (is-identity-registered user-principal)) ERR-IDENTITY-EXISTS)
    (asserts! (is-valid-string display-name) ERR-INVALID-INPUT)
    (try! (log-identity-activity "REGISTRATION" none))
    (ok (map-set user-identities
      user-principal
      {
        identity-active: true,
        display-name: display-name,
        registration-timestamp: current-timestamp,
        last-modified-timestamp: current-timestamp,
        backup-address: none,
        identity-score: u1,
        verification-level: u0
      }
    ))
  )
)

(define-public (set-identity-attribute (attribute-name (string-ascii 32)) (attribute-value (string-ascii 256)))
  (let
    (
      (user-principal tx-sender)
      (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
      (safe-attribute-name (unwrap! (as-max-len? attribute-name u32) ERR-INVALID-INPUT))
      (safe-attribute-value (unwrap! (as-max-len? attribute-value u256) ERR-INVALID-INPUT))
    )
    (asserts! (is-identity-registered user-principal) ERR-IDENTITY-NOT-FOUND)
    (asserts! (and (is-valid-string safe-attribute-name) (is-valid-string safe-attribute-value)) ERR-INVALID-INPUT)
    (try! (log-identity-activity "ATTRIBUTE_SET" (some safe-attribute-name)))
    (ok (map-set identity-attributes
      {identity-owner: user-principal, attribute-name: safe-attribute-name}
      {
        attribute-value: safe-attribute-value,
        is-verified: false,
        verification-authority: none,
        verification-timestamp: none,
        verification-expiry: none,
        verification-metadata: none
      }
    ))
  )
)

(define-public (verify-identity-attribute (identity-owner principal) (attribute-name (string-ascii 32)))
  (let
    (
      (verifier-principal tx-sender)
      (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
      (verification-valid-until (+ current-timestamp VERIFICATION-TIMEOUT))
      (safe-attribute-name (unwrap! (as-max-len? attribute-name u32) ERR-INVALID-INPUT))
    )
    (asserts! (is-identity-registered identity-owner) ERR-IDENTITY-NOT-FOUND)
    (asserts! (is-identity-registered verifier-principal) ERR-UNAUTHORIZED-VERIFIER)
    (asserts! (is-valid-string safe-attribute-name) ERR-INVALID-INPUT)
    (try! (log-identity-activity "ATTRIBUTE_VERIFIED" (some safe-attribute-name)))
    (ok (map-set identity-attributes
      {identity-owner: identity-owner, attribute-name: safe-attribute-name}
      (merge (unwrap! (map-get? identity-attributes {identity-owner: identity-owner, attribute-name: safe-attribute-name}) ERR-ATTRIBUTE-NOT-FOUND)
        {
          is-verified: true,
          verification-authority: (some verifier-principal),
          verification-timestamp: (some current-timestamp),
          verification-expiry: (some verification-valid-until),
          verification-metadata: (some "Verified by authorized verifier")
        }
      )
    ))
  )
)

(define-public (add-identity-delegate 
  (delegate-address principal) 
  (delegate-permissions (list 10 (string-ascii 32))) 
  (delegation-duration uint)
  (can-sub-delegate bool)
  (metadata (string-ascii 256)))
  (let
    (
      (identity-owner tx-sender)
      (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
      (safe-delegate-permissions (unwrap! (as-max-len? delegate-permissions u10) ERR-INVALID-INPUT))
      (safe-metadata (unwrap! (as-max-len? metadata u256) ERR-INVALID-INPUT))
      (safe-delegation-duration (if (is-valid-delegation-duration delegation-duration) 
                                    delegation-duration 
                                    MAX-DELEGATION-DURATION))
      (delegation-expiry-time (+ current-timestamp safe-delegation-duration))
    )
    (asserts! (is-identity-registered identity-owner) ERR-IDENTITY-NOT-FOUND)
    (asserts! (is-identity-registered delegate-address) ERR-DELEGATE-NOT-FOUND)
    (asserts! (and (is-valid-permission-list safe-delegate-permissions) (is-valid-string safe-metadata)) ERR-INVALID-INPUT)
    (try! (log-identity-activity "DELEGATE_ADDED" none))
    (ok (map-set identity-delegates
      {identity-owner: identity-owner, delegate-address: delegate-address}
      {
        granted-permissions: safe-delegate-permissions,
        delegation-expiry: delegation-expiry-time,
        delegation-metadata: safe-metadata,
        can-sub-delegate: can-sub-delegate
      }
    ))
  )
)

(define-public (remove-identity-delegate (delegate-address principal))
  (let
    (
      (identity-owner tx-sender)
    )
    (asserts! (is-identity-registered identity-owner) ERR-IDENTITY-NOT-FOUND)
    (asserts! (is-some (map-get? identity-delegates {identity-owner: identity-owner, delegate-address: delegate-address})) ERR-DELEGATE-NOT-FOUND)
    (try! (log-identity-activity "DELEGATE_REMOVED" none))
    (ok (map-delete identity-delegates {identity-owner: identity-owner, delegate-address: delegate-address}))
  )
)

(define-public (set-backup-address (backup-address principal))
  (let
    (
      (identity-owner tx-sender)
      (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
    )
    (asserts! (is-identity-registered identity-owner) ERR-IDENTITY-NOT-FOUND)
    (asserts! (is-identity-registered backup-address) ERR-IDENTITY-NOT-FOUND)
    (try! (log-identity-activity "BACKUP_SET" none))
    (ok (map-set user-identities
      identity-owner
      (merge (unwrap! (map-get? user-identities identity-owner) ERR-IDENTITY-NOT-FOUND)
        {
          backup-address: (some backup-address),
          last-modified-timestamp: current-timestamp
        }
      )
    ))
  )
)

;; Private helper functions
(define-private (log-identity-activity (activity-type (string-ascii 32)) (activity-data (optional (string-ascii 64))))
  (let
    (
      (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
    )
    (map-set identity-activity-log
      {identity-owner: tx-sender, activity-timestamp: current-timestamp}
      {
        activity-type: activity-type,
        activity-data: activity-data,
        initiated-by: tx-sender
      }
    )
    (ok true)
  )
)

(define-private (is-delegate-authorized (identity-owner principal) (delegate-address principal) (required-permission (string-ascii 32)))
  (match (map-get? identity-delegates {identity-owner: identity-owner, delegate-address: delegate-address})
    delegate-info (and
      (>= (unwrap! (get-block-info? time (- block-height u1)) false)
          (get delegation-expiry delegate-info))
      (is-some (index-of (get granted-permissions delegate-info) required-permission))
    )
    false
  )
)

(define-private (update-identity-score (user-address principal) (score-change int))
  (match (map-get? user-identities user-address)
    user-identity 
    (let
      (
        (current-score (get identity-score user-identity))
        (new-score (+ current-score (if (> score-change 0) u1 u0)))
      )
      (ok (map-set user-identities
        user-address
        (merge user-identity { identity-score: new-score })
      ))
    )
    ERR-IDENTITY-NOT-FOUND
  )
)

;; Contract initialization
(begin
  (map-set user-identities
    CONTRACT-OWNER
    {
      identity-active: true,
      display-name: "System Administrator",
      registration-timestamp: block-height,
      last-modified-timestamp: block-height,
      backup-address: none,
      identity-score: u100,
      verification-level: u5
    }
  )
  (ok true)
)