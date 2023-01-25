<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Auth;
use Validator;
use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }
    public function register(Request $request)
    {
        /*
            |   validate data
        */
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        /*
            |   validate data status fails
        */
        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        /*
            |   validate data status true
        */
        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        /*
            |   response data ['message', 'user', 'status code']
        */
        return response()->json([
            'message' => 'User successfully registered!',
            'user' => $user
        ], 201);
    }
    
    public function login(Request $request)
    {
        /*
            |   validate data
        */
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        /*
            |   validate data status fails
        */
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        /*
            |   attempt method: push data to auth()
            |   auth()->attempt([
            |       'name' => 'value',
            |       'age' => 'value',
            |   ]);
        */
        if(!$token=auth()->attempt($validator->validated())){
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }

    public function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => (auth()->factory()->getTTL() * 60),
            'user' => auth()->user(),
        ]);
    }

    public function profile(){
        return response()->json(auth()->user());
    }

    public function logout(){
        auth()->logout();
        return response()->json([
            'message' => 'User logged out'
        ], 201);
    }
}
