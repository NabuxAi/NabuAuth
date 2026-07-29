<?php

namespace App\Services;

class EcosystemAppRegistry
{
    public static function all(): array
    {
        return [
            [
                'id' => 'nabuwrite',
                'name' => 'NabuWrite',
                'description' => 'AI Narrative & Long-form Content Generation Engine',
                'icon' => 'pencil-square',
                'url' => 'https://write.nabuxai.com',
                'sso_url' => 'https://auth.nabuxai.com/oauth/authorize?client_id=nabuwrite&redirect_uri=https://write.nabuxai.com/auth/callback&response_type=code',
                'badge' => 'Active',
            ],
            [
                'id' => 'nabugate',
                'name' => 'NabuGate AI',
                'description' => 'Unified AI LLM, Vision & Multi-model Gateway',
                'icon' => 'cpu-chip',
                'url' => 'https://gate.nabuxai.com',
                'sso_url' => 'https://auth.nabuxai.com/oauth/authorize?client_id=nabugate&redirect_uri=https://gate.nabuxai.com/auth/callback&response_type=code',
                'badge' => 'Active',
            ],
            [
                'id' => 'nabudesk',
                'name' => 'NabuDesk',
                'description' => 'Omnichannel AI Support & Operations Workspace',
                'icon' => 'chat-bubble-left-right',
                'url' => 'https://desk.nabuxai.com',
                'sso_url' => 'https://auth.nabuxai.com/oauth/authorize?client_id=nabudesk&redirect_uri=https://desk.nabuxai.com/auth/callback&response_type=code',
                'badge' => 'Active',
            ],
            [
                'id' => 'nabugen',
                'name' => 'NabuGen',
                'description' => 'Multimodal Image, Video & Asset Generation',
                'icon' => 'photo',
                'url' => 'https://gen.nabuxai.com',
                'sso_url' => 'https://auth.nabuxai.com/oauth/authorize?client_id=nabugen&redirect_uri=https://gen.nabuxai.com/auth/callback&response_type=code',
                'badge' => 'Active',
            ],
            [
                'id' => 'nabuvoice',
                'name' => 'NabuVoice',
                'description' => 'Text-to-Speech & Speech Synthesis Platform',
                'icon' => 'speaker-wave',
                'url' => 'https://voice.nabuxai.com',
                'sso_url' => 'https://auth.nabuxai.com/oauth/authorize?client_id=nabuvoice&redirect_uri=https://voice.nabuxai.com/auth/callback&response_type=code',
                'badge' => 'Active',
            ],
        ];
    }
}
