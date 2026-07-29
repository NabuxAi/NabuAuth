<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('phone')->nullable()->unique();
            $table->string('password');
            $table->string('avatar_url')->nullable();
            $table->boolean('is_active')->default(true);
            $table->rememberToken();
            $table->timestamps();
        });

        Schema::create('oauth_clients', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('client_id')->unique();
            $table->string('client_secret');
            $table->text('redirect_uris');
            $table->boolean('is_confidential')->default(true);
            $table->timestamps();
        });

        Schema::create('oauth_codes', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('client_id');
            $table->string('code')->unique();
            $table->text('scopes')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });

        Schema::create('wallets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->bigInteger('balance_cents')->default(0);
            $table->string('currency')->default('OMR');
            $table->timestamps();
        });

        Schema::create('wallet_transactions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('wallet_id')->constrained()->cascadeOnDelete();
            $table->string('type'); // topup, debit, refund
            $table->bigInteger('amount_cents');
            $table->bigInteger('balance_after_cents');
            $table->string('description');
            $table->json('meta')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('wallet_transactions');
        Schema::dropIfExists('wallets');
        Schema::dropIfExists('oauth_codes');
        Schema::dropIfExists('oauth_clients');
        Schema::dropIfExists('users');
    }
};
