<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;
// https://developers.tiktok.com/doc/login-kit-overview

class TikTok extends OAuth2
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
        'user.info.basic',
        'video.list'
    ];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'tiktok';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://www.tiktok.com/v2/auth/authorize/?' . \http_build_query([
            'client_key' => $this->appID,
            'redirect_uri' => $this->callback,
            'scope' => \implode(',', $this->getScopes()),
            'response_type' => 'code',
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
                'https://open-api.tiktok.com/oauth/access_token/',
                [],
                \http_build_query([
                    'client_key' => $this->appID,
                    'client_secret' => $this->appSecret,
                    'code' => $code,
                    'grant_type' => 'authorization_code'
                ])
            ), true);

            if (isset($this->tokens['data'])) {
                $this->tokens = $this->tokens['data'];
            }
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
            'https://open-api.tiktok.com/oauth/refresh_token/',
            [],
            \http_build_query([
                'client_key' => $this->appID,
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken
            ])
        ), true);

        if (isset($this->tokens['data'])) {
            $this->tokens = $this->tokens['data'];
        }

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

        return $user['open_id'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        // TikTok API doesn't provide email information
        return '';
    }

    /**
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        // TikTok API doesn't provide email verification status
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

        return $user['display_name'] ?? '';
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
                'https://open-api.tiktok.com/user/info/',
                [
                    'Authorization: Bearer ' . \urlencode($accessToken)
                ]
            ), true);

            $this->user = $response['data'] ?? [];
        }

        return $this->user;
    }
}
