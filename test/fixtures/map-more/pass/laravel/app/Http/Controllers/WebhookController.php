<?php

namespace App\Http\Controllers;

use App\Models\Account;
use Illuminate\Http\Request;

class WebhookController extends Controller
{
    public function pay(Request $request)
    {
        $payload = $request->getContent();
        $expected = hash_hmac('sha256', $payload, config('services.pay.secret'));
        if (! hash_equals($expected, (string) $request->header('X-Pay-Signature'))) {
            abort(400);
        }
        Account::find($request->input('account'))->update(['paid' => true]);

        return response()->noContent();
    }
}
