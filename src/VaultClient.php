<?php
declare(strict_types=1);

namespace Onshore;

final class VaultError extends \RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $errorCode, string $message, public readonly ?string $policy = null, public readonly ?string $requestId = null)
    {
        parent::__construct("$errorCode: $message");
    }
}

/**
 * Onshore client. Handles token refresh, batching and retries. Detokenize
 * fails closed: when the vault cannot answer it throws, and never returns a token as
 * if it were the value. Needs PHP 8.1+ with the sodium and curl extensions.
 */
final class VaultClient
{
    private const BATCH = 500;
    private ?string $token = null;
    private int $expiry = 0;
    private string $secretKey;

    /** @param array<int, mixed> $curlOptions extra options, such as a CA bundle */
    public function __construct(private string $baseUrl, private string $serviceAccountId, private string $keyId, string $seedB64, private int $maxAttempts = 4, private array $curlOptions = [])
    {
        $seed = base64_decode($seedB64, true);
        if ($seed === false || strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('the private key must be a base64 Ed25519 seed');
        }
        $this->secretKey = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    private static function b64u(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    private function assertion(): string
    {
        $now = time();
        $head = self::b64u(json_encode(['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => $this->keyId]));
        $body = self::b64u(json_encode(['iss' => $this->serviceAccountId, 'sub' => $this->serviceAccountId, 'aud' => 'onshore', 'jti' => bin2hex(random_bytes(16)), 'iat' => $now, 'exp' => $now + 120]));
        return "$head.$body." . self::b64u(sodium_crypto_sign_detached("$head.$body", $this->secretKey));
    }

    private function bearer(): string
    {
        if ($this->token !== null && time() < $this->expiry - 60) {
            return $this->token;
        }
        $r = $this->raw('POST', '/v1/auth/token', ['assertion' => $this->assertion()], null);
        $this->token = $r['access_token'];
        $this->expiry = time() + (int) $r['expires_in'];
        return $this->token;
    }

    /** @return array<string, mixed> */
    private function raw(string $method, string $path, ?array $body, ?string $token, ?string $purpose = null): array
    {
        $last = null;
        $json = $body === null ? null : json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        for ($i = 0; $i < $this->maxAttempts; $i++) {
            if ($i > 0) {
                $wait = min(2000000, 100000 * (2 ** $i));
                usleep(intdiv($wait, 2) + random_int(0, intdiv($wait, 2)));
            }
            $ch = curl_init($this->baseUrl . $path);
            $headers = ['Content-Type: application/json'];
            if ($token !== null) {
                $headers[] = "Authorization: Bearer $token";
            }
            if ($purpose !== null) {
                // Header values can't hold line breaks; a purpose is one line.
                $headers[] = 'X-RV-Purpose: ' . str_replace(["\r", "\n"], ' ', $purpose);
            }
            $opts = [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_HTTPHEADER => $headers];
            if ($json !== null) {
                $opts[CURLOPT_POSTFIELDS] = $json;
            }
            curl_setopt_array($ch, $opts + $this->curlOptions);
            $resp = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($resp === false) {
                $last = new VaultError(0, 'network_error', 'the vault cannot be reached');
                continue;
            }
            $data = json_decode((string) $resp, true) ?? [];
            if ($status < 300) {
                return $data;
            }
            $err = new VaultError($status, $data['error']['code'] ?? 'error', $data['error']['message'] ?? "status $status", $data['error']['policy'] ?? null, $data['request_id'] ?? null);
            if ($status === 401 && $token !== null) {
                $this->token = null;
                throw $err;
            }
            if ($status === 429 || $status >= 500) {
                $last = $err;
                continue;
            }
            throw $err;
        }
        throw $last;
    }

    private function call(string $path, array $body): array
    {
        return $this->raw('POST', $path, $body, $this->bearer());
    }

    private function send(string $method, string $path, ?array $body = null, ?string $purpose = null): array
    {
        return $this->raw($method, $path, $body, $this->bearer(), $purpose);
    }

    private static function seg(string $s): string
    {
        return rawurlencode($s);
    }

    /**
     * Stores values, batching at 500. With continueOnError good items are stored and each bad one
     * gets an 'error'. With dryRun nothing is stored.
     *
     * @param list<array{field:string,value:string,subject_ref?:string}> $items
     * @return list<array{index:int,token?:string,existing?:bool,error?:array{code:string,message:string}}>
     */
    public function tokenize(string $vault, array $items, bool $continueOnError = false, bool $dryRun = false): array
    {
        $out = [];
        foreach (array_chunk($items, self::BATCH) as $n => $chunk) {
            foreach ($this->call("/v1/vaults/$vault/tokenize", ['items' => $chunk, 'continue_on_error' => $continueOnError, 'dry_run' => $dryRun])['results'] as $r) {
                $r['index'] += $n * self::BATCH;
                $out[] = $r;
            }
        }
        return $out;
    }

    /**
     * Returns values as policy allows. Each item is a token string, or ['token' => ..., 'redaction' => 'masked'|'token_only'].
     *
     * @param list<string|array{token:string,redaction?:string}> $tokens
     * @return list<array{index:int,decision?:string,value?:string,policy?:string,error?:array}>
     */
    public function detokenize(string $vault, array $tokens, string $purpose, bool $continueOnError = false): array
    {
        $out = [];
        foreach (array_chunk($tokens, self::BATCH) as $n => $chunk) {
            $items = array_map(fn ($t) => is_string($t) ? ['token' => $t] : $t, $chunk);
            foreach ($this->call("/v1/vaults/$vault/detokenize", ['items' => $items, 'purpose' => $purpose, 'continue_on_error' => $continueOnError])['results'] as $r) {
                $r['index'] += $n * self::BATCH;
                $out[] = $r;
            }
        }
        return $out;
    }

    public function lookup(string $vault, string $field, string $value): string
    {
        return $this->call("/v1/vaults/$vault/lookup", ['field' => $field, 'value' => $value])['token'];
    }

    public function residentCheck(string $vault, string $token, string $check, string $arg, string $purpose): bool
    {
        return (bool) $this->call("/v1/vaults/$vault/resident/check", compact('token', 'check', 'arg', 'purpose'))['result'];
    }

    /**
     * Stores several fields for one person. All are stored or none.
     *
     * @param array<string,string> $fields
     * @return array{id:string,tokens:array<string,string>}
     */
    public function insertRecord(string $vault, array $fields, ?string $subjectRef = null): array
    {
        $r = $this->call("/v1/vaults/$vault/records", ['fields' => (object) $fields, 'subject_ref' => $subjectRef ?? '']);
        return ['id' => $r['id'], 'tokens' => $r['tokens']];
    }

    /** Reads every field of a record, each as the access rules allow. @return array<string,array> */
    public function getRecord(string $vault, string $id, string $purpose): array
    {
        return $this->send('GET', "/v1/vaults/$vault/records/" . self::seg($id), null, $purpose)['fields'] ?? [];
    }

    /** Changes the value behind a new-token-each-time (cell) token. The token stays the same. */
    public function updateValue(string $vault, string $token, string $value): void
    {
        $this->send('PUT', "/v1/vaults/$vault/tokens/" . self::seg($token), ['value' => $value]);
    }

    /**
     * Lists the people in a vault. Keys: query, field_type, has_reveals, flagged, created_after,
     * created_before, sort, dir, limit (1 to 200, default 50), offset.
     *
     * @return array{subjects:list<array>,total:int}
     */
    public function searchSubjects(string $vault, array $query = []): array
    {
        $r = $this->call("/v1/vaults/$vault/subjects/search", $query === [] ? ['query' => ''] : $query);
        return ['subjects' => $r['subjects'] ?? [], 'total' => (int) ($r['total'] ?? 0)];
    }

    /** One person and their fields, each masked at most. Never returns real values. */
    public function getSubject(string $vault, string $subjectId): array
    {
        $r = $this->send('GET', "/v1/vaults/$vault/subjects/" . self::seg($subjectId));
        unset($r['request_id']);
        return $r;
    }

    /** Exports a person's fields for an access request, as access rules allow. @return list<array> */
    public function exportSubject(string $vault, string $subjectId, string $purpose): array
    {
        return $this->send('GET', "/v1/vaults/$vault/subjects/" . self::seg($subjectId) . '/export', null, $purpose)['fields'] ?? [];
    }

    /** While restricted, nothing about the person reveals. Returns the new state. */
    public function restrictSubject(string $vault, string $subjectId, bool $restricted, string $purpose): bool
    {
        return (bool) $this->call("/v1/vaults/$vault/subjects/" . self::seg($subjectId) . '/restrict', ['restricted' => $restricted, 'purpose' => $purpose])['restricted'];
    }

    /** Erases everything held on a person. Returns how many records went. */
    public function eraseSubject(string $vault, string $subjectId, string $purpose): int
    {
        return (int) ($this->send('DELETE', "/v1/vaults/$vault/subjects/" . self::seg($subjectId), null, $purpose)['erased_records'] ?? 0);
    }

    /**
     * Finds identifiers in text. Offsets are byte offsets, which suit PHP's substr().
     *
     * @param list<string>|null $entities
     * @return array{entities:list<array>,text?:string,ruleset_version?:int}
     */
    public function detect(string $text, ?string $vault = null, bool $tokenize = false, ?array $entities = null, bool $includeShadow = false): array
    {
        $body = ['text' => $text, 'tokenize' => $tokenize, 'include_shadow' => $includeShadow];
        if ($vault !== null) {
            $body['vault'] = $vault;
        }
        if ($entities !== null) {
            $body['entities'] = $entities;
        }
        $r = $this->call('/v1/detect', $body);
        unset($r['request_id']);
        return $r;
    }

    /** Reports what a batch holds before a job sends it on. Only counts are kept. */
    public function checkFlow(string $vault, string $flow, string $text): array
    {
        return $this->call("/v1/vaults/$vault/flows/" . self::seg($flow) . '/check', ['text' => $text]);
    }

    /**
     * Mints a single-use token for a collect or reveal component. Call from your server only.
     * Keys: kind, origin, fields, tokens, purpose, on_behalf_of, subject_ref, bind_ip, ttl_seconds.
     *
     * @return array{client_token:string,expires_at:string}
     */
    public function createClientToken(string $vault, array $request): array
    {
        $r = $this->call("/v1/vaults/$vault/client-tokens", $request);
        return ['client_token' => $r['client_token'], 'expires_at' => $r['expires_at']];
    }

    /**
     * Cloaks text before it goes to an AI model or outside service. Send a profile ID or options, not both.
     *
     * @param array<string,string>|null $options
     * @return array{text:string,changed:array<string,int>,id?:string}
     */
    public function cloak(string $vault, string $text, ?string $profileId = null, ?array $options = null, int $keepDays = 0): array
    {
        $body = ['text' => $text];
        if ($profileId !== null) {
            $body['profile_id'] = $profileId;
        }
        if ($options !== null) {
            $body['options'] = (object) $options;
        }
        if ($keepDays > 0) {
            $body['keep_days'] = $keepDays;
        }
        $r = $this->call("/v1/vaults/$vault/cloak", $body);
        unset($r['request_id']);
        return $r;
    }

    /** Restores placeholders in text as far as the access rules allow. @return array{text:string,decisions:array<string,string>} */
    public function uncloak(string $vault, string $twinId, string $text, string $purpose): array
    {
        $r = $this->call("/v1/vaults/$vault/uncloak", ['id' => $twinId, 'text' => $text, 'purpose' => $purpose]);
        return ['text' => $r['text'], 'decisions' => $r['decisions'] ?? []];
    }

    /** Deletes a digital twin before it expires. */
    public function deleteTwin(string $vault, string $twinId): void
    {
        $this->send('DELETE', "/v1/vaults/$vault/twins/" . self::seg($twinId));
    }

    /**
     * Checks a webhook from Onshore. Pass the raw body (file_get_contents('php://input')) and the
     * X-Rv-Signature header. During a secret rotation either of two signatures is enough.
     */
    public static function verifyWebhook(string $secret, string $rawBody, string $signatureHeader, int $toleranceSeconds = 300, ?int $now = null): bool
    {
        $at = null;
        $sigs = [];
        foreach (explode(',', $signatureHeader) as $part) {
            [$k, $v] = array_pad(explode('=', trim($part), 2), 2, '');
            if ($k === 't' && ctype_digit($v)) {
                $at = (int) $v;
            } elseif ($k === 'v1') {
                $sigs[] = $v;
            }
        }
        if ($at === null || abs(($now ?? time()) - $at) > $toleranceSeconds) {
            return false;
        }
        $want = hash_hmac('sha256', "$at." . $rawBody, $secret);
        $ok = false;
        foreach ($sigs as $s) {
            $ok = hash_equals($want, $s) || $ok;
        }
        return $ok;
    }
}
