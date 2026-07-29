<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Wallet extends Model
{
    protected $fillable = [
        'user_id',
        'balance_cents',
        'currency',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function transactions(): HasMany
    {
        return $this->hasMany(WalletTransaction::class);
    }

    public function debit(int $cents, string $description, array $meta = []): WalletTransaction
    {
        $this->balance_cents -= $cents;
        $this->save();

        return $this->transactions()->create([
            'type' => 'debit',
            'amount_cents' => -$cents,
            'balance_after_cents' => $this->balance_cents,
            'description' => $description,
            'meta' => $meta,
        ]);
    }

    public function credit(int $cents, string $description, array $meta = []): WalletTransaction
    {
        $this->balance_cents += $cents;
        $this->save();

        return $this->transactions()->create([
            'type' => 'topup',
            'amount_cents' => $cents,
            'balance_after_cents' => $this->balance_cents,
            'description' => $description,
            'meta' => $meta,
        ]);
    }
}
