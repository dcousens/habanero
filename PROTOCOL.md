# sambal

### Assumptions
This protocol assumes TLS for authentication, encryption and the prevention of replay attacks.

## Methods

### Setup
On the Server
1. Select a random 32-byte sequence $e$

### Notarization
On a Client (or Attacking) device
1. Select a random $pin$, where $pin \in \{x \in \Bbb Z \mid 0 \le x \le 9999\}$
1. Select a random 32-byte sequence $d$
1. $P = HMAC_{SHA256}(Key=d, Data=pin)$
1. Send $P$ to the Server

On the Server
1. Select a random 32-byte sequence $I$
1. $K = HMAC_{SHA512}(Key=e, Data=I \parallel P)$
1. Split $K$ into two 32-byte sequences $K_{pepper}$ and $K_{verify}$
1. Send $I \parallel K_{pepper} \parallel K_{verify}$ to the Client

The Client can then derive a key-encryption-key:

$$
kek = HKDF(Salt=d \parallel K_{pepper}, Data=pin)
$$

The Client discards $P$, $K_{pepper}$ and $kek$.
The Client retains $d$, $I$ and $K_{verify}$ for retrieval.

##### Rationale
$pin$ is a 4-digit PIN code, it *should be* cryptographically random.

$d$ is a cryptographically random 256-bit Client secret for deriving $P$.
$P$ is transmitted instead of $pin$ to prevent the Server from knowing $pin$.

$I$ is a cryptographically random 256-bit identifier for authentication and attempt-limiting.
$I$ is not provided by the Client to prevent Notarization from acting as a method of $K_{pepper}$ retrieval.
$I$ is not derived from $P$ to prevent $I$ from acting as a cryptographic oracle enabling the online brute-force of $pin$.

$K_{verify}$ is a hash commitment to $I \parallel P$ by the Server, for $P$ verification on $K_{pepper}$ retrieval.
$K_{verify}$ additionally removes the requirement for a Server-side registry of sanctioned $I$ values.

$kek$ is derived from $d \parallel K_{pepper}$ to prevent a weak $K_{pepper}$ value enabling $pin$ to be trivially brute-forced off-line.


### Retrieval of $K_{pepper}$
On a Client (or Attacking) device
1. Select a $pin$, where $pin \in \{x \in \Bbb Z \mid 0 \le x \le 9999\}$
1. $P = HMAC_{SHA256}(Key=d, Data=pin)$
1. Send $I \parallel P \parallel K_{verify}$ to the Server

On the Server

###### Limit I
1. If $I \in {attempts}$, and $I_{attempts} \gt 5$, reject

###### Verify P
1. $K' = HMAC_{SHA512}(Key=e, Data=I \parallel P)$
1. Split $K'$ into two 32-byte sequences $K'_{pepper}$ and $K'_{verify}$
1. If $K'_{verify} \ne K_{verify}$, go to [Denial](######Denial)
1. Send $K'_{pepper}$ and $I_{attempts}$ to Client
1. Reset $I_{attempts}$ to $0$, skip [Denial](######Denial)

###### Denial
1. Record $I_{attempts}$ as $I_{attempts} + 1$ in $attempts$, reject

The Client can then derive a key-encryption-key:

$$
kek = HKDF(Salt=d \parallel K_{pepper}, Data=pin)
$$

The Client discards $P$, $K_{pepper}$ and $kek$.


#### Rationale
$I_{attempts}$ is revealed to the Client to enable expectation matching (notification of "N password attempt(s)").
In typical application usage, $d$ is never shared; therefore a mismatch of expectations is synonymous with a notification of compromise for the local device.


## Attack Vectors
Although this protocol assumes TLS,  transport layer attacks are still explored below.

#### 1. Transport compromise (Notarization)
> An Attacker captures $P$

The Attacker cannot replay $P$ idempotently, as $K_{pepper}$ is derived from $I$, which is different each time.

> An Attacker captures $I \parallel K_{pepper} \parallel K_{verify}$

The Attacker can execute a denial-of-service attack via attempting (and failing) $K_{pepper}$ retrieval.


#### 2. Transport compromise (Retrieval)
> An Attacker captures $I \parallel P \parallel K_{verify}$

If $P$ is notarized with $K_{verify}$, the Attacker can replay Retrieval to reveal $K_{pepper}$.

If $P$ is not notarized, the Attacker can execute a denial-of-service attack by varying $P$.

> An Attacker captures $K'_{pepper}$ and $I_{attempts}$ to Client

This denial-of-service could be reset by external validation of the Clients identity.
To prevent brute-force by social engineering, a $I_{attempts}$ value should never be reset twice.


#### 3. Local compromise
> An Attacker compromises $d$, $I$ and $K_{verify}$

If $d$ is compromised, $K_{pepper}$ cannot be retrieved without $pin$, providing the Attacker $I_{attempts}$ to guess $pin$ before denial of service.

An Attacker could strategically limit themselves to $<5$ attempts, leaving the remaining attempts for the actual User.
The Attacker could then wait until the Client successfully retrieves a $K_{pepper}$, resetting $I_{attempts}$, enabling the Attacker to continue brute-forcing online.
This attack is ideally mitigated by a notification to the User of the mismatch in expectations for the $I_{attempts}$ value.


#### 4. Local compromise and transport compromise
> An Attacker compromises $d$, $I$, $K_{verify}$, and ($P$ or $K_{pepper}$)

This is a catastrophic compromise.

If an Attacker has $d$ and $K_{pepper}$, $kek$ can be derived.

If an Attacker has $d$, $I$, $K_{verify}$ and $P$, $pin$ can be trivially brute-forced off-line, $K_{pepper}$ retrieved, and then $kek$ derived.


#### 5. Server compromise
> An Attacker compromises $e$ or the $I_{attempts}$ database

If an Attacker has $e$, any existing or subsequent local compromise can now be assumed as catastrophic.

With database compromise, $I_{attempts}$ can be assumed as $0$ for any retrieval, enabling online brute-forcing of $pin$.


#### 6. Server and local compromise
> An Attacker compromises $d$, $I$, $K_{verify}$, and $e$

This is a catastrophic compromise.

$pin$ can be trivially brute-forced off-line, $K_{pepper}$ derived, and then $kek$ derived.


### Conclusions
If both the Server and Client is compromised, it can be assumed that the Client's data has been trivially, and catastrophically decrypted off-line.

If the Client, and the Client's connection is compromised, and $P$ or $K_{pepper}$ captured, it can be assumed that the Client's data has been trivially, and catastrophically decrypted off-line.

If the Client is compromised, the Client has approximately a $0.05\%$ probability of catastrophic loss, depending on the strength and randomness of $pin$.
Although compromised, the Client could safely copy $d$, $K_{verify}$ and then re-enter $pin$ on a non-compromised device, if necessary. Re-notarization is strongly recommended in this event.

If the Server is compromised, the Client cannot suffer a catastrophic decryption without local compromise.


## Appendix
$5$ is chosen as the upper limit of $I_{attempts}$ as it provides approximately a ~$0.05\%$ probability of random success by an attacker.
However [DataGenetics](http://www.datagenetics.com/blog/september32012/) shows us that $20.552\%$ of $pin$ codes can be found within 5 attempts.
Whether uniform $pin$ distribution is enforced is a UX consideration, and ignored in this draft.
