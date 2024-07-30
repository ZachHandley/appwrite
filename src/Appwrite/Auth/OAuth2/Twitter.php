<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// 1. OAuth 2.0 Authorization Code Flow with PKCE: https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code
// 2. OAuth 2.0 User Context: https://developer.twitter.com/en/docs/authentication/oauth-2-0/user-context
// 3. User lookup endpoint: https://developer.twitter.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me

class X extends OAuth2
{
    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    /**
     * @var array
     */
    protected array $scopes = [
        'tweet.read',
        'users.read',
        'offline.access'
    ];

    /**
     * @var string
     */
    protected string $version = '2';

    /**
     * @var string
     */
    protected string $codeVerifier = '';

    /**
     * @var string
     */
    protected string $codeChallenge = '';

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'Twitter';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        $this->codeVerifier = $this->generateCodeVerifier();
        $this->codeChallenge = $this->generateCodeChallenge($this->codeVerifier);

        return 'https://twitter.com/i/oauth2/authorize?' . \http_build_query([
            'response_type' => 'code',
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'scope' => \implode(' ', $this->getScopes()),
            'state' => \json_encode($this->state),
            'code_challenge' => $this->codeChallenge,
            'code_challenge_method' => 'S256'
        ]);
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $this->tokens = \json_decode($this->request(
                'POST',
                'https://api.twitter.com/2/oauth2/token',
                ['Content-Type: application/x-www-form-urlencoded'],
                \http_build_query([
                    'code' => $code,
                    'grant_type' => 'authorization_code',
                    'client_id' => $this->appID,
                    'redirect_uri' => $this->callback,
                    'code_verifier' => $this->codeVerifier
                ])
            ), true);
        }

        return $this->tokens;
    }

    /**
     * @param string $refreshToken
     *
     * @return array
     */
    public function refreshTokens(string $refreshToken): array
    {
        $this->tokens = \json_decode($this->request(
            'POST',
            'https://api.twitter.com/2/oauth2/token',
            ['Content-Type: application/x-www-form-urlencoded'],
            \http_build_query([
                'refresh_token' => $refreshToken,
                'grant_type' => 'refresh_token',
                'client_id' => $this->appID
            ])
        ), true);

        return $this->tokens;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['id'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        // X API v2 doesn't provide email information through this endpoint
        return '';
    }

    /**
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        // X API v2 doesn't provide email verification status through this endpoint
        return false;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['username'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $response = \json_decode($this->request(
                'GET',
                'https://api.twitter.com/2/users/me',
                ['Authorization: Bearer ' . $accessToken],
                '',
                ['user.fields' => 'id,name,username']
            ), true);

            $this->user = $response['data'] ?? [];
        }

        return $this->user;
    }

    /**
     * Generate a code verifier for PKCE
     *
     * @return string
     */
    protected function generateCodeVerifier(): string
    {
        $random = \bin2hex(\random_bytes(32));
        return \rtrim(\strtr(\base64_encode($random), '+/', '-_'), '=');
    }

    /**
     * Generate a code challenge for PKCE
     *
     * @param string $codeVerifier
     * @return string
     */
    protected function generateCodeChallenge(string $codeVerifier): string
    {
        $hash = \hash('sha256', $codeVerifier, true);
        return \rtrim(\strtr(\base64_encode($hash), '+/', '-_'), '=');
    }
}
