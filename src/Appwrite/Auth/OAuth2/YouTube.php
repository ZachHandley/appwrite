<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// 1. Using OAuth 2.0 for Web Server Applications: https://developers.google.com/youtube/v3/guides/auth/server-side-web-apps
// 2. Channels: list endpoint: https://developers.google.com/youtube/v3/docs/channels/list

class YouTube extends OAuth2
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
        'https://www.googleapis.com/auth/youtube.readonly'
    ];

    /**
     * @var string
     */
    protected string $version = 'v3';

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'youtube';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        $state = $this->generateState();

        return 'https://accounts.google.com/o/oauth2/v2/auth?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'response_type' => 'code',
            'scope' => \implode(' ', $this->getScopes()),
            'access_type' => 'offline',
            'include_granted_scopes' => 'true',
            'state' => $state
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
                'https://oauth2.googleapis.com/token',
                ['Content-Type: application/x-www-form-urlencoded'],
                \http_build_query([
                    'code' => $code,
                    'client_id' => $this->appID,
                    'client_secret' => $this->appSecret,
                    'redirect_uri' => $this->callback,
                    'grant_type' => 'authorization_code'
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
            'https://oauth2.googleapis.com/token',
            ['Content-Type: application/x-www-form-urlencoded'],
            \http_build_query([
                'client_id' => $this->appID,
                'client_secret' => $this->appSecret,
                'refresh_token' => $refreshToken,
                'grant_type' => 'refresh_token'
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
        // YouTube API doesn't provide email verification status
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

        return $user['name'] ?? '';
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
                'https://www.googleapis.com/youtube/v3/channels',
                ['Authorization: Bearer ' . $accessToken],
                '',
                ['part' => 'snippet', 'mine' => 'true']
            ), true);

            if (isset($response['items'][0]['snippet'])) {
                $this->user = [
                    'id' => $response['items'][0]['id'],
                    'name' => $response['items'][0]['snippet']['title'],
                    // Note: YouTube API doesn't provide email in this endpoint
                    'email' => ''
                ];
            }
        }

        return $this->user;
    }

    /**
     * Generate a random state value
     *
     * @return string
     */
    protected function generateState(): string
    {
        return \bin2hex(\random_bytes(16));
    }
}
