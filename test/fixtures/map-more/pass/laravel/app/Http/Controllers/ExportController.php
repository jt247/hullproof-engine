<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class ExportController extends Controller
{
    public function index(Request $request)
    {
        return response()->json(User::whereKey($request->user()->id)->get());
    }
}
