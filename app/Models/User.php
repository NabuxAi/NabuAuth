<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory;

    protected $fillable = [
        'name',
        'email',
        'phone',
        'password',
        'avatar_url',
        'is_active',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    public function wallet(): HasOne
    {
        return $this->hasOne(Wallet::class);
    }
}
