use neon::prelude::*;
use mongodb::{bson::{doc, Uuid}, options::ClientOptions, Client, Database};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Utc};

// JWT secret key.
const JWT_SECRET: &[u8] = b"thisisasecretkey";

// User model.
#[derive(Serialize, Deserialize)]
struct User {
    #[serde(rename = "_id", default = "Uuid::new")]
    id: Uuid,
    name: String,
    email: String,
    username: String,
    password: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    created_at: DateTime<Utc>,
}

// JWT Claims.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    username: String,
    exp: usize,
}

// Initialize MongoDB connection.
async fn init_mongo() -> Database {
    let uri = String::from("mongodb://localhost:27017");
    let db_name = String::from("auth_service");

    let client_options = ClientOptions::parse(&uri).await.expect("Invalid MongoDB URI");
    let client = Client::with_options(client_options).expect("Failed to initialize MongoDB client");

    client.database(&db_name)
}

// Hash a password.
fn hash_password(mut cx: FunctionContext) -> JsResult<JsString> {
    let password = cx.argument::<JsString>(0)?.value(&mut cx);
    let hashed = hash(password, DEFAULT_COST).expect("Failed to hash password");
    Ok(cx.string(hashed))
}

// Verify a password.
fn verify_password(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let password = cx.argument::<JsString>(0)?.value(&mut cx);
    let hashed_password = cx.argument::<JsString>(1)?.value(&mut cx);
    let is_valid = verify(&password, &hashed_password).unwrap_or(false);
    Ok(cx.boolean(is_valid))
}

// Generate a JWT token.
fn generate_token(mut cx: FunctionContext) -> JsResult<JsString> {
    let username = cx.argument::<JsString>(0)?.value(&mut cx);

    // Define the expiration time (1 hour from now).
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::hours(1))
        .expect("Failed to set expiration time")
        .timestamp() as usize;

    let claims = Claims { username, exp: expiration };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .expect("Failed to generate token");

    Ok(cx.string(token))
}

// Verify a JWT token.
fn verify_token(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let token = cx.argument::<JsString>(0)?.value(&mut cx);

    let validation = Validation::default();
    let is_valid = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(JWT_SECRET),
        &validation,
    )
    .is_ok();

    Ok(cx.boolean(is_valid))
}

// Register a user in MongoDB.
fn register_user(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let name = cx.argument::<JsString>(0)?.value(&mut cx);
    let email = cx.argument::<JsString>(1)?.value(&mut cx);
    let username = cx.argument::<JsString>(2)?.value(&mut cx);
    let password = cx.argument::<JsString>(3)?.value(&mut cx);

    // Hash the password.
    let hashed_password = hash(password, DEFAULT_COST).expect("Failed to hash password");
    let user = User {
        id: Uuid::new(),
        name,
        email,
        username,
        password: hashed_password,
        created_at: Utc::now(),
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        let db = init_mongo().await;
        let collection = db.collection::<User>("users");

        collection.insert_one(user).await
    });

    match result {
        Ok(_) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false)),
    }
}

// Login user and generate JWT.
fn login_user(mut cx: FunctionContext) -> JsResult<JsString> {
    let username = cx.argument::<JsString>(0)?.value(&mut cx);
    let password = cx.argument::<JsString>(1)?.value(&mut cx);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        let db = init_mongo().await;
        let collection = db.collection::<User>("users");

        let user = collection.find_one(doc! { "username": &username }).await;

        if let Ok(Some(user)) = user {
            if verify(&password, &user.password).unwrap_or(false) {
                let expiration = Utc::now()
                    .checked_add_signed(chrono::Duration::hours(1))
                    .expect("Failed to set expiration time")
                    .timestamp() as usize;

                let claims = Claims {
                    username,
                    exp: expiration,
                };

                return Some(
                    encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(JWT_SECRET),
                    )
                    .expect("Failed to generate token"),
                );
            }
        }

        None
    });

    match result {
        Some(token) => Ok(cx.string(token)),
        None => cx.throw_error("Invalid username or password"),
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hash_password", hash_password)?;
    cx.export_function("verify_password", verify_password)?;
    cx.export_function("generate_token", generate_token)?;
    cx.export_function("verify_token", verify_token)?;
    cx.export_function("register_user", register_user)?;
    cx.export_function("login_user", login_user)?;
    Ok(())
}
