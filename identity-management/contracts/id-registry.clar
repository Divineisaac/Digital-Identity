;; Identity Smart Contract
;; Description: A comprehensive digital identity management system
;; Features: Identity registration, profile management, attribute verification,
;;          identity delegation, and recovery mechanisms

;; Constants for configuration
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MAX-ATTRIBUTE-LENGTH u256)
(define-constant MAX-DELEGATE-PERMISSIONS u10)
(define-constant VERIFICATION-TIMEOUT u2880) ;; 48 hours in blocks

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
        attribute-value: (string-utf8 256),
        is-verified: bool,
        verification-authority: (optional principal),
        verification-timestamp: (optional uint),
        verification-expiry: (optional uint),
        verification-metadata: (optional (string-utf8 256))
    }
)

;; Manages delegation relationships and permissions
(define-map identity-delegates
    {identity-owner: principal, delegate-address: principal}
    {
        granted-permissions: (list 10 (string-ascii 32)),
        delegation-expiry: uint,
        delegation-metadata: (string-utf8 256),
        can-sub-delegate: bool
    }
)

;; Activity tracking for security
(define-map identity-activity-log
    {identity-owner: principal, activity-timestamp: uint}
    {
        activity-type: (string-ascii 32),
        activity-data: (optional (string-utf8 256)),
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

;; Public functions

(define-public (register-new-identity (display-name (string-ascii 64)))
    (let
        (
            (user-principal tx-sender)
            (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
        )
        (asserts! (not (is-identity-registered user-principal)) ERR-IDENTITY-EXISTS)
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

(define-public (update-display-name (updated-name (string-ascii 64)))
    (let
        (
            (user-principal tx-sender)
            (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
        )
        (asserts! (is-identity-registered user-principal) ERR-IDENTITY-NOT-FOUND)
        (try! (log-identity-activity "NAME_UPDATE" (some updated-name)))
        (ok (map-set user-identities
            user-principal
            (merge (unwrap! (map-get? user-identities user-principal) ERR-IDENTITY-NOT-FOUND)
                {
                    display-name: updated-name,
                    last-modified-timestamp: current-timestamp
                }
            )
        ))
    )
)

(define-public (set-identity-attribute (attribute-name (string-ascii 32)) (attribute-value (string-utf8 256)))
    (let
        (
            (user-principal tx-sender)
            (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
        )
        (asserts! (is-identity-registered user-principal) ERR-IDENTITY-NOT-FOUND)
        (try! (log-identity-activity "ATTRIBUTE_SET" (some attribute-name)))
        (ok (map-set identity-attributes
            {identity-owner: user-principal, attribute-name: attribute-name}
            {
                attribute-value: attribute-value,
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
        )
        (asserts! (is-identity-registered identity-owner) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-identity-registered verifier-principal) ERR-UNAUTHORIZED-VERIFIER)
        (try! (log-identity-activity "ATTRIBUTE_VERIFIED" (some attribute-name)))
        (ok (map-set identity-attributes
            {identity-owner: identity-owner, attribute-name: attribute-name}
            (merge (unwrap! (map-get? identity-attributes {identity-owner: identity-owner, attribute-name: attribute-name}) ERR-ATTRIBUTE-NOT-FOUND)
                {
                    is-verified: true,
                    verification-authority: (some verifier-principal),
                    verification-timestamp: (some current-timestamp),
                    verification-expiry: (some verification-valid-until),
                    verification-metadata: (some (concat "Verified by: " (to-ascii verifier-principal)))
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
    (metadata (string-utf8 256)))
    (let
        (
            (identity-owner tx-sender)
            (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
            (delegation-expiry-time (+ current-timestamp delegation-duration))
        )
        (asserts! (is-identity-registered identity-owner) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-identity-registered delegate-address) ERR-DELEGATE-NOT-FOUND)
        (try! (log-identity-activity "DELEGATE_ADDED" (some (to-ascii delegate-address))))
        (ok (map-set identity-delegates
            {identity-owner: identity-owner, delegate-address: delegate-address}
            {
                granted-permissions: delegate-permissions,
                delegation-expiry: delegation-expiry-time,
                delegation-metadata: metadata,
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
        (try! (log-identity-activity "DELEGATE_REMOVED" (some (to-ascii delegate-address))))
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
        (try! (log-identity-activity "BACKUP_SET" (some (to-ascii backup-address))))
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

(define-private (log-identity-activity (activity-type (string-ascii 32)) (activity-data (optional (string-utf8 256))))
    (let
        (
            (current-timestamp (unwrap! (get-block-info? time (- block-height u1)) ERR-SYSTEM-FAILURE))
        )
        (ok (map-set identity-activity-log
            {identity-owner: tx-sender, activity-timestamp: current-timestamp}
            {
                activity-type: activity-type,
                activity-data: activity-data,
                initiated-by: tx-sender
            }
        ))
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
    ;; Initialize any necessary contract state here
    (try! (map-set user-identities
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
    ))
)