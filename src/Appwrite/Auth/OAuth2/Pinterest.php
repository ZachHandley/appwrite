<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// https://developers.pinterest.com/docs/getting-started/authentication-and-scopes/

class Pinterest extends OAuth2
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
        'user_accounts:read',
        'pins:read'
    ];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'pinterest';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://www.pinterest.com/oauth/?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'response_type' => 'code',
            'scope' => \implode(',', $this->getScopes()),
            'state' => \json_encode($this->state)
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
                'https://api.pinterest.com/v5/oauth/token',
                ['Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret)],
                \http_build_query([
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'redirect_uri' => $this->callback
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
            'https://api.pinterest.com/v5/oauth/token',
            ['Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret)],
            \http_build_query([
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken
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
        $user = $this->getUser($accessToken);

        return $user['email'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        // Pinterest API doesn't provide email verification status
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
                'https://api.pinterest.com/v5/user_account',
                ['Authorization: Bearer ' . $accessToken]
            ), true);

            $this->user = $response ?? [];
        }

        return $this->user;
    }
}
