<?php

use App\Modules\User\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;


Route::group([
    'prefix' => 'api/users',
    'middleware' => ['auth:sanctum'],
], function ($router) {
    Route::post('/WHReset_manual_', [UserController::class, 'WHReset_manual_']);
    Route::get('/wh_index', [UserController::class, 'wh_index']);
    Route::get('/', [UserController::class, 'index']);
    Route::post('/mensuelWHReset', [UserController::class, 'mensuelWHReset']);
    Route::post('/logout', [UserController::class, 'logout']);
    Route::post('/delete', [UserController::class,'delete']);
    Route::put('/updatepass', [UserController::class,'updatePassword']);
    Route::put('/resetpass', [UserController::class,'resetPassword']);
    Route::put('/update', [UserController::class,'update']);
    Route::post('/drivers' , [UserController::class,'getDrivers']);
    Route::post('/getDriversActiveList_byF' , [UserController::class,'getDriversActiveList_byF']);
    Route::post('/getDriversActiveList_all' , [UserController::class,'getDriversActiveList_all']);
    Route::post('/getById', [UserController::class,'getById']);
});

Route::group([
    'prefix' => 'api/users',
    // 'middleware' => ['cors'],
], function ($router) {
    Route::post('/addFromAPI', [UserController::class,'addFromAPI']);
    Route::post('/register', [UserController::class,'register']);
    Route::post('/login', [UserController::class,'login']);
});
