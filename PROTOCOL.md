# habanero
Habanero is an attempt-limiting, remote pepper provisioning protocol for users who want to limit the amount of explorable key space by an Attacker.

## Summary
If a User has encrypted data on their Laptop, and their Laptop is compromised, typically an Attacker could copy the encrypted data and begin a brute-force attack against the passphrase or encryption key.
Typically this is partially mitigated by either a high-entropy key, or through the use of a cryptographic key derivation function (KDF) with a high work-factor.

For Users who use low-entropy passphrases, the result is near-immediate decryption of their encrypted data.

With Habanero, an Attacker would instead be limited to trying only 5 passphrase guesses before being remotely 'locked out' of decrypting the data.

Habanero uses a deterministic [cryptographic pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography)) for each passphrase, retrieved remotely from a 3rd party whom you trust to safely track the number of attempts tried.
The trusted 3rd party can maintain a minimal state of only tracking failed attempts.

For a low-entropy passphrase, such as a 4 digit PIN, this can be a highly effective method of minimizing the risk of catastrophic decryption by an Attacker,  with a decryption probability of only 0.05% (using a limit of maximum 5 guesses).
Increasing the entropy of the passphrase directly decreases the probability of catastrophic decryption.

By tracking the number of failed attempts, a 3rd party can additionally support the reporting of failed passphrase attempts to the User as a canary for a potential compromise.


### Assumptions
This protocol assumes TLS for authentication, encryption and the prevention of replay attacks.

## Methods

### Setup
On the Server
1. Select a random 32-byte sequence $e$

### Commitment
On a Client (or Attacking) device
1. Select a random $pin$, where $pin \in \{x \in \Bbb Z \mid 0 \le x \le 9999\}$
1. Select a random 32-byte sequence $d$
1. $P = HMAC_{SHA256}(Key=d, Data=pin)$
1. Send $P$ to the Server

On the Server
1. Select a random 32-byte sequence $I$
1. $K = HMAC_{SHA512}(Key=e, Data=I \parallel P)$
1. Split $K$ into two 32-byte sequences $K_{verify}$ and $K_{pepper}$
1. Send $\{I \mid K_{verify} \mid K_{pepper}\}$ to the Client

The Client can then derive a key-encryption-key:

$$
kek = KDF(Salt=d \parallel K_{pepper}, Data=pin)
$$

The Client discards $P$, $K_{pepper}$ and $kek$.
The Client retains $d$, $I$ and $K_{verify}$ for retrieval.

##### Rationale
$pin$ is a 4-digit PIN code, it *should be* cryptographically random.

$d$ is a cryptographically random 256-bit Client secret for deriving $P$.
$P$ is transmitted instead of $pin$ to prevent the Server from knowing $pin$.

$I$ is a cryptographically random 256-bit identifier for authentication and attempt-limiting.
$I$ is not provided by the Client to prevent Commitment from acting as a method of $K_{pepper}$ retrieval.
$I$ is not derived from $P$ to prevent $I$ from acting as a cryptographic oracle enabling the online brute-force of $pin$.

$K_{verify}$ is a hash commitment to $I \parallel P$ by the Server, for $P$ verification on $K_{pepper}$ retrieval.
$K_{verify}$ additionally removes the requirement for a Server-side registry of sanctioned $I$ values.

$kek$ should use $d$ as a salt, combined with $K_{pepper}$ to prevent a weak $K_{pepper}$ value that could enable $pin$ to be trivially brute-forced off-line.


### Retrieval of $K_{pepper}$
On a Client (or Attacking) device
1. Select a $pin$, where $pin \in \{x \in \Bbb Z \mid 0 \le x \le 9999\}$
1. $P = HMAC_{SHA256}(Key=d, Data=pin)$
1. Send $\{I \mid K_{verify} \mid P\}$ to the Server

On the Server

###### Limit I
1. If $I \in attempted$, and $I_{attempts} \gte 5$, reject

###### Verify P
1. $K' = HMAC_{SHA512}(Key=e, Data=I \parallel P)$
1. Split $K'$ into two 32-byte sequences $K'_{pepper}$ and $K'_{verify}$
1. If $K'_{verify} \ne K_{verify}$, go to [Denial](######Denial)
1. Send $K'_{pepper}$ and $I_{attempts}$ to Client
1. Send $\{K'_{pepper} \mid I_{attempts}\}$ to the Client
1. Reset $I_{attempts}$ to $0$, skip [Denial](######Denial)

###### Denial
1. Record $I_{attempts}$ as $I_{attempts} + 1$ in $attempted$, reject

The Client can then derive a key-encryption-key:

$$
kek = KDF(Salt=d \parallel K_{pepper}, Data=pin)
$$

The Client discards $P$, $K_{pepper}$ and $kek$.

The comparison $K'_{verify} \ne K_{verify}$ should be executed in constant time.

#### Rationale
$I_{attempts}$ is revealed to the Client to enable expectation matching (notification of "N passphrase attempt(s)").
In typical application usage, $d$ is never shared; therefore a mismatch of expectations is synonymous with a notification of compromise for the local device.

$I_{attempts}$ values should be indexed by $H(I)$, where $H$ is a cryptographic hash function, to prevent any timing attacks that may reveal indexed $I$ values.

The $I_{attempts}$ limit of $5$ was selected as it provides an approximate ~$0.05\%$ probability of success for an Attacker when using a 4-digit $pin$.

However, if $pin$ distribution is not uniform, [DataGenetics](http://www.datagenetics.com/blog/september32012/) shows that $20.552\%$ of $pin$ codes are typically guessed in 5 attempts.
The enforcement of whether a $pin$ is randomly selected is a UX consideration, and ignored in this protocol.


## Attack Vectors
Although this protocol assumes TLS, transport layer attacks are still explored below.

#### 1. Transport compromise (Commitment)
> An Attacker captures $P$

The Attacker cannot replay $P$ idempotently, as $K_{pepper}$ is derived from $I$, which is different each time.

> An Attacker captures $I$, $K_{verify}$ and $K_{pepper}$

The Attacker can execute a denial-of-service attack via attempting (and failing) $K_{pepper}$ retrieval.

This denial-of-service could be reset by external validation of the Clients identity.   To prevent brute-force via social engineering of the 3rd party, a $I_{attempts}$ value should never be reset twice.


#### 2. Transport compromise (Retrieval)
> An Attacker captures $I$, $P$ and $K_{verify}$

If $K_{verify}$ is a legitimate commitment, and $P$ the pre-image for that commitment, the Attacker can replay this data by Retrieval to reveal $K_{pepper}$.

Otherwise, the Attacker can only execute a denial-of-service attack by varying $P$ or $K_{verify}$.

> An Attacker captures $K'_{pepper}$ and $I_{attempts}$ to Client

This is NOT a catastrophic compromise without Local compromise.


#### 3. Local compromise
> An Attacker compromises $d$, $I$ and $K_{verify}$

If $d$ is compromised, $K_{pepper}$ cannot be retrieved without $pin$, providing the Attacker $I_{attempts}$ to guess $pin$ before denial of service.

An Attacker could strategically limit themselves to $<5$ attempts, leaving any remaining attempts for the actual User.
The Attacker could then wait until the Client successfully retrieves a $K_{pepper}$, resetting $I_{attempts}$, enabling the Attacker to continue brute-forcing online.
This attack is ideally mitigated by a notification to the User of the mismatch in expectations for the $I_{attempts}$ value.


#### 4. Local compromise and transport compromise
> An Attacker compromises $d$, $I$, $K_{verify}$, and ($P$ or $K_{pepper}$)

This is a catastrophic compromise.

If an Attacker has $d$ and $K_{pepper}$, $pin$ can be trivially brute-forced off-line (provided a local validation oracle exists, e.g data encrypted with $kek$).

If an Attacker has $d$, $I$, $K_{verify}$ and $P$, $pin$ can be trivially brute-forced off-line using $P$ as a validation oracle.


#### 5. Server compromise
> An Attacker compromises $e$ or the $I_{attempts}$ database

If an Attacker has $e$, any existing or subsequent local compromise can now be assumed as catastrophic.

With database compromise, $I_{attempts}$ can be assumed as $0$ for any retrieval, enabling online brute-forcing of $pin$.


#### 6. Server and local compromise
> An Attacker compromises $d$, $I$, $K_{verify}$, and $e$

This is a catastrophic compromise.

$pin$ can be trivially brute-forced off-line, $K_{pepper}$ derived, and then $kek$ derived.


#### 7. Non constant-time comparison for $K_{verify}$
> An Attacker takes advantage of the comparison $K'_{verify} \ne K_{verify}$ mistakenly leaking timing information.

If an implementation leaks timing information about $K'_{verify} \ne K_{verify}$, then $K'_{verify}$ could theoretically be revealed in less than 256 attempts.

An Attacker would keep the $I$ and $P$ values constant, varying the Attacker provided $K_{verify}$ until it equates the remotely computed $K'_{verify}$.  With a valid $K_{verify}$,  the Attacker can now reset $I_{attempts}$ on demand.

As in [3.](#3-local-compromise), an Attacker would strategically limit themselves to $<5$ attempts, leaving any remaining attempts for the actual User to reset $I_{attempts}$ authentically to enable them to complete the search space.

This is measureably less work than attempting every possible $pin$ online.
Combined with a local compromise, $I_{attempts}$ can continuously be assumed to be $0$, enabling online brute-forcing of $pin$.


### Conclusions
If both the Server and Client is compromised, it can be assumed that the Client's data has been trivially, and catastrophically decrypted off-line.

If the Client, and the Client's connection is compromised, and $P$ or $K_{pepper}$ captured, it can be assumed that the Client's data has been trivially, and catastrophically decrypted off-line.

If the Client is compromised, the Client has approximately a $0.05\%$ probability of catastrophic loss, depending on the strength and randomness of $pin$.
Although compromised, the Client could safely copy $d$, $K_{verify}$ and then re-enter $pin$ on a non-compromised device, if necessary. Re-commitment is strongly recommended in this event.

If the Server is compromised, the Client cannot suffer a catastrophic decryption without local compromise.
