<?php

use App\Http\Controllers\Admin\UserController;
use App\Http\Controllers\ExportController;
use App\Http\Controllers\ImportController;
use App\Http\Controllers\ItemController;
use App\Http\Controllers\LoginController;
use App\Http\Controllers\NoteController;
use App\Http\Controllers\UploadController;
use App\Http\Controllers\WebhookController;
use Illuminate\Support\Facades\Route;

Route::post('/login', [LoginController::class, 'store']);
Route::post('/webhooks/pay', [WebhookController::class, 'pay']);
Route::post('/notes', [NoteController::class, 'store']);
Route::get('/api/export', [ExportController::class, 'index']);

Route::middleware('auth')->group(function () {
    Route::delete('/notes/{note}', [NoteController::class, 'destroy']);
    Route::get('/api/items', [ItemController::class, 'index']);
    Route::post('/api/import', [ImportController::class, 'store']);
    Route::post('/api/upload', [UploadController::class, 'store']);
    Route::post('/admin/users/{user}/role', [UserController::class, 'role']);
});
