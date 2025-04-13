from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_file, session
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os
import io
import uuid
import time  # For adding delays
from database import get_db, close_db
from concurrent.futures import wait
import concurrent.futures

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# File to store keys and tokens
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
key_file = os.path.join(BASE_DIR, "keys.json")

# Ensure the keys file exists
if not os.path.exists(key_file):
    with open(key_file, "w") as file:
        json.dump({}, file)

def load_keys():
    db = get_db()
    keys = db.execute('SELECT * FROM keys').fetchall()
    key_data = {}
    for key in keys:
        tokens = db.execute('SELECT * FROM tokens WHERE key_id = ?', (key['id'],)).fetchall()
        key_data[key['user_key']] = {
            "total_limit": key['total_limit'],
            "available_limit": key['available_limit'],
            "tokens": [dict(token) for token in tokens]
        }
    return key_data

def save_keys(keys):
    db = get_db()
    for user_key, key_data in keys.items():
        # Update or insert key
        db.execute('INSERT OR REPLACE INTO keys (user_key, total_limit, available_limit) VALUES (?, ?, ?)',
                   (user_key, key_data['total_limit'], key_data['available_limit']))
        key_id = db.execute('SELECT id FROM keys WHERE user_key = ?', (user_key,)).fetchone()['id']
        # Delete existing tokens for the key
        db.execute('DELETE FROM tokens WHERE key_id = ?', (key_id,))
        # Insert new tokens
        for token in key_data['tokens']:
            db.execute('INSERT INTO tokens (key_id, account_name, token) VALUES (?, ?, ?)',
                       (key_id, token['account_name'], token['token']))
    db.commit()

# Admin password (change this to a strong password)
ADMIN_PASSWORD = "Azure@5964@#9812#"

# Admin login route
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash("Admin login successful.")
            return redirect(url_for("admin_panel"))
        else:
            flash("Invalid password.")
    return render_template("admin_login.html")

# Admin logout route
@app.route("/admin/logout", methods=["GET", "POST"])
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Admin logged out.")
    return redirect(url_for("index"))

# Admin panel route
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if request.method == "POST":
        if 'add_key' in request.form:
            # Add a manual key
            user_key = request.form.get("user_key")
            if user_key:
                keys[user_key] = {"total_limit": 0, "available_limit": 0, "tokens": []}  # Default limit is 0
                save_keys(keys)
                flash(f"Key '{user_key}' added successfully.")
            else:
                flash("Please enter a valid key.")

        elif 'generate_key' in request.form:
            # Generate a random key
            user_key = str(uuid.uuid4())  # Generate a random UUID
            keys[user_key] = {"total_limit": 0, "available_limit": 0, "tokens": []}  # Default limit is 0
            save_keys(keys)
            flash(f"Random key '{user_key}' generated successfully.")

        elif 'delete_key' in request.form:
            # Delete a key
            key_to_delete = request.form.get("key_to_delete")
            if key_to_delete in keys:
                del keys[key_to_delete]
                save_keys(keys)
                flash(f"Key '{key_to_delete}' deleted successfully.")
            else:
                flash("Key not found.")

        elif 'update_limit' in request.form:
            # Update limit for a key
            key_to_update = request.form.get("key_to_update")
            new_limit = int(request.form.get("new_limit"))
            if key_to_update in keys:
                # Ensure the key has the required fields
                if "total_limit" not in keys[key_to_update]:
                    keys[key_to_update]["total_limit"] = 0
                if "available_limit" not in keys[key_to_update]:
                    keys[key_to_update]["available_limit"] = 0

                # Calculate the new available_limit
                current_available_limit = keys[key_to_update]["available_limit"]
                keys[key_to_update]["total_limit"] += new_limit
                keys[key_to_update]["available_limit"] += new_limit
                save_keys(keys)
                flash(f"Limit updated successfully for key '{key_to_update}'. New total limit: {keys[key_to_update]['total_limit']}, New available limit: {keys[key_to_update]['available_limit']}.")
            else:
                flash("Key not found.")

    # Prepare data to show keys and their linked tokens
    key_token_pairs = []
    for key, key_data in keys.items():
        # Ensure the key has the required fields
        if "total_limit" not in key_data:
            key_data["total_limit"] = 0
        if "available_limit" not in key_data:
            key_data["available_limit"] = 0

        tokens = key_data.get("tokens", [])
        total_limit = key_data["total_limit"]
        available_limit = key_data["available_limit"]
        key_token_pairs.append({
            "key": key,
            "tokens": tokens,
            "total_limit": total_limit,
            "available_limit": available_limit
        })

    return render_template("admin_panel.html", key_token_pairs=key_token_pairs)

# Add token route
@app.route("/add_token", methods=["POST"])
def add_token():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    account_name = request.form.get("account_name")
    token = request.form.get("token")
    keys = load_keys()

    # Get the user key from the session
    user_key = session['user_key']

    # Debugging: Print the current keys before adding the token
    print("Current keys before adding token:", keys)

    # Check if the key exists in keys.json
    if user_key in keys:
        # Add the new token to the key's token list
        keys[user_key]["tokens"].append({
            "account_name": account_name,
            "token": token
        })
    else:
        # If the key doesn't exist, create a new entry
        keys[user_key] = {
            "tokens": [{
                "account_name": account_name,
                "token": token
            }]
        }

    # Debugging: Print the updated keys after adding the token
    print("Updated keys after adding token:", keys)

    # Save the updated keys to the file
    save_keys(keys)
    flash("Token added successfully.")
    return redirect(url_for("index"))


# Add this route to view tokens
@app.route("/view_tokens")
def view_tokens():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No tokens found for your key.")
        return redirect(url_for("index"))

    tokens = keys[user_key]["tokens"]
    return render_template("view_tokens.html", tokens=tokens)

@app.route("/admin/add_token/<key>", methods=["POST"])
def admin_add_token(key):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    account_name = request.form.get("account_name")
    token = request.form.get("token")

    keys = load_keys()

    if key in keys:
        keys[key]["tokens"].append({
            "account_name": account_name,
            "token": token
        })
        save_keys(keys)
        flash(f"Token added successfully for key '{key}'.")
    else:
        flash(f"Key '{key}' not found.")

    return redirect(url_for("admin_panel"))

@app.route("/admin/remove_token/<key>/<int:token_index>", methods=["POST"])
def admin_remove_token(key, token_index):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if key in keys:
        tokens = keys[key]["tokens"]
        if token_index < len(tokens):
            removed_token = tokens.pop(token_index)
            save_keys(keys)
            flash(f"Token '{removed_token['token']}' removed successfully for key '{key}'.")
        else:
            flash("Invalid token index.")
    else:
        flash(f"Key '{key}' not found.")

    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_key/<key>", methods=["POST"])
def admin_delete_key(key):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if key in keys:
        del keys[key]
        save_keys(keys)
        flash(f"Key '{key}' deleted successfully.")
    else:
        flash(f"Key '{key}' not found.")

    return redirect(url_for("admin_panel"))


@app.route("/admin/edit_token/<key>/<int:token_index>", methods=["GET", "POST"])
def admin_edit_token(key, token_index):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if key not in keys:
        flash(f"Key '{key}' not found.")
        return redirect(url_for("admin_panel"))

    tokens = keys[key]["tokens"]
    if token_index >= len(tokens):
        flash("Invalid token index.")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        account_name = request.form.get("account_name")
        token = request.form.get("token")

        tokens[token_index] = {
            "account_name": account_name,
            "token": token
        }
        save_keys(keys)
        flash(f"Token updated successfully for key '{key}'.")
        return redirect(url_for("admin_panel"))

    token = tokens[token_index]
    return render_template("edit_token.html", key=key, token_index=token_index, token=token)

# Add this route to edit a token
@app.route("/edit_token/<int:token_index>", methods=["GET", "POST"])
def edit_token(token_index):
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No tokens found for your key.")
        return redirect(url_for("index"))

    tokens = keys[user_key]["tokens"]
    if token_index >= len(tokens):
        flash("Invalid token index.")
        return redirect(url_for("view_tokens"))

    if request.method == "POST":
        account_name = request.form.get("account_name")
        token = request.form.get("token")
        tokens[token_index] = {"account_name": account_name, "token": token}
        save_keys(keys)
        flash("Token updated successfully.")
        return redirect(url_for("view_tokens"))

    token = tokens[token_index]
    return render_template("edit_token.html", token=token, token_index=token_index)

# Add this route to delete a token
@app.route("/delete_token/<int:token_index>", methods=["POST"])
def delete_token(token_index):
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No tokens found for your key.")
        return redirect(url_for("index"))

    tokens = keys[user_key]["tokens"]
    if token_index >= len(tokens):
        flash("Invalid token index.")
        return redirect(url_for("view_tokens"))

    del tokens[token_index]
    save_keys(keys)
    flash("Token deleted successfully.")
    return redirect(url_for("view_tokens"))

# Function to validate root password
def validate_password(password):
    if (
        len(password) >= 14
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and sum(c in "!@#$%^&*()-_+=<>?/" for c in password) >= 2
    ):
        return True
    return False

# Function to create a Linode instance with rate limiting
def create_linode_instance(instance_number, results, image, region, instance_type, root_password, token, user_key):
    max_retries = 2
    retry_delay = 3
    
    for retry in range(max_retries + 1):
        try:
            if retry > 0:
                time.sleep(retry_delay * retry)  # Progressive delay for retries
            
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            label = f"{region}-{instance_type}-{instance_number}-{timestamp}"
            data = {
                "image": image,
                "private_ip": False,
                "region": region,
                "type": instance_type,
                "label": label,
                "root_pass": root_password
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
            
            # Add timeout to the request
            response = requests.post(
                "https://api.linode.com/v4/linode/instances",
                headers=headers,
                data=json.dumps(data),
                timeout=60  # Increased timeout to 60 seconds
            )
            
            if response.status_code in [200, 201]:
                instance_data = response.json()
                if not instance_data.get("ipv4"):
                    raise Exception("No IP address returned from Linode API")
                ip = instance_data.get("ipv4", [])[0]
                
                # Update available_limit for the user's key with proper database handling
                db = get_db()
                try:
                    # Get current limits with row locking
                    key_data = db.execute(
                        'SELECT id, available_limit FROM keys WHERE user_key = ? FOR UPDATE',
                        (user_key,)
                    ).fetchone()
                    
                    if key_data and key_data['available_limit'] > 0:
                        # Update the limit
                        db.execute(
                            'UPDATE keys SET available_limit = available_limit - 1 WHERE id = ? AND available_limit > 0',
                            (key_data['id'],)
                        )
                        db.commit()
                    else:
                        raise Exception("No available limit for the key")
                except Exception as db_error:
                    db.rollback()
                    raise Exception(f"Database error while updating limit: {str(db_error)}")
                finally:
                    db.close()
                
                return ip
            else:
                error_msg = response.json().get("errors", [{"reason": "Unknown error"}])[0].get("reason")
                if retry < max_retries and (
                    "rate limit" in error_msg.lower() or 
                    "timeout" in error_msg.lower() or
                    "try again" in error_msg.lower()
                ):
                    continue  # Retry on rate limits or temporary errors
                raise Exception(f"Failed to create Linode instance {instance_number}: {error_msg}")
                
        except requests.Timeout:
            if retry < max_retries:
                continue
            raise Exception(f"Timeout while creating instance {instance_number}")
        except requests.RequestException as e:
            if retry < max_retries:
                continue
            raise Exception(f"Network error while creating instance {instance_number}: {str(e)}")
        except Exception as e:
            if retry < max_retries and "rate limit" in str(e).lower():
                continue
            raise Exception(f"Error creating instance {instance_number}: {str(e)}")
    
    raise Exception(f"Failed to create instance {instance_number} after {max_retries} retries")

# Function to delete a Linode instance with error handling
def delete_linode_instance(instance_id, token):
    try:
        url = f"https://api.linode.com/v4/linode/instances/{instance_id}"
        headers = {
            "Authorization": f"Bearer {token}"
        }
        response = requests.delete(url, headers=headers, timeout=30)  # Add 30 second timeout
        
        if response.status_code in [200, 204]:
            return True
        else:
            error_msg = response.json().get("errors", [{"reason": "Unknown error"}])[0].get("reason")
            raise Exception(f"Failed to delete instance {instance_id}: {error_msg}")
            
    except requests.Timeout:
        raise Exception(f"Timeout while deleting instance {instance_id}")
    except requests.RequestException as e:
        raise Exception(f"Network error while deleting instance {instance_id}: {str(e)}")
    except Exception as e:
        raise Exception(f"Error deleting instance {instance_id}: {str(e)}")

# Function to list all Linode instances
def list_linode_instances(token):
    url = "https://api.linode.com/v4/linode/instances"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("data", [])
    else:
        flash(f"Failed to retrieve Linode instances: {response.json()}")
        return []

@app.route("/")
def index():
    keys = load_keys()
    if 'user_key' in session:
        user_key = session['user_key']
        if user_key in keys:
            tokens = {token["account_name"]: token["token"] for token in keys[user_key]["tokens"]}
            available_limit = keys[user_key].get("available_limit", 0)
            total_limit = keys[user_key].get("total_limit", 0)
            return render_template("index.html", tokens=tokens, keys=keys, available_limit=available_limit, total_limit=total_limit)
    return render_template("index.html", tokens={}, keys=keys, available_limit=0, total_limit=0)

@app.route("/validate_key", methods=["POST"])
def validate_key():
    user_key = request.form.get("user_key")
    keys = load_keys()
    if user_key in keys:
        session['user_key'] = user_key
        flash("Key validated successfully.")
    else:
        flash("Invalid key.")
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])  # Allow POST for logout
def logout():
    session.pop('user_key', None)  # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('index'))

# Create instances route with background task
@app.route("/create_instances", methods=["POST"])
def create_instances():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No token found for your key.")
        return redirect(url_for("index"))

    available_limit = keys[user_key].get("available_limit", 0)
    num_instances = int(request.form.get("num_instances"))

    if num_instances > available_limit:
        flash(f"You have reached your limit. You can only create {available_limit} more instances.")
        return redirect(url_for("index"))

    token = request.form.get("token")
    image = request.form.get("image")
    region = request.form.get("region")
    instance_type = request.form.get("instance_type")
    root_password = request.form.get("root_password")

    if not validate_password(root_password):
        flash("Invalid password. Please try again.")
        return redirect(url_for("index"))

    ips = []
    errors = []
    try:
        # Process instances in smaller batches with progressive delays
        batch_size = 5  # Process 5 instances at a time
        total_batches = (num_instances + batch_size - 1) // batch_size
        base_delay = 2  # Base delay between batches in seconds
        
        for batch in range(total_batches):
            start_idx = batch * batch_size + 1
            end_idx = min((batch + 1) * batch_size + 1, num_instances + 1)
            batch_instances = range(start_idx, end_idx)
            batch_ips = []
            
            # Calculate progressive delay based on batch number
            current_delay = min(base_delay * (1 + batch * 0.5), 10)  # Max 10 seconds delay
            if batch > 0:
                time.sleep(current_delay)  # Progressive delay between batches
            
            # Set a longer timeout for the ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                futures = []
                # Submit tasks with individual timeouts
                for i in batch_instances:
                    future = executor.submit(
                        create_linode_instance,
                        i, batch_ips, image, region, instance_type,
                        root_password, token, user_key
                    )
                    futures.append(future)
                
                # Wait for current batch with a timeout
                timeout_per_instance = 120  # 2 minutes per instance
                batch_timeout = timeout_per_instance * len(batch_instances)
                
                # Process futures as they complete
                for future in futures:
                    try:
                        ip = future.result(timeout=batch_timeout)
                        if ip:
                            ips.append(ip)
                    except concurrent.futures.TimeoutError:
                        errors.append(f"Instance in batch {batch + 1} timed out")
                    except Exception as e:
                        errors.append(str(e))
            
            # Update progress after each batch
            progress_msg = f"Completed batch {batch + 1}/{total_batches} ({len(ips)} instances created so far)"
            print(progress_msg)  # For server logs
            
            # If we have too many errors, stop processing
            error_threshold = 0.3  # 30% error rate threshold
            if len(errors) / (start_idx) > error_threshold and batch > 2:
                errors.append(f"Stopping due to high error rate ({len(errors)} errors in {start_idx} attempts)")
                break

        # Prepare response
        if ips:
            file_content = f"Region: {region}\nInstance Type: {instance_type}\nRoot Password: {root_password}\n"
            if errors:
                file_content += "\nErrors encountered:\n" + "\n".join(errors) + "\n\n"
            file_content += f"Successfully created {len(ips)} out of {num_instances} instances.\n\nIPs:\n"
            file_content += "\n".join(ips)
            
            file_stream = io.BytesIO(file_content.encode('utf-8'))
            file_stream.seek(0)
            
            # Update the database with final count if there were any failures
            if len(ips) < num_instances:
                db = get_db()
                try:
                    # Calculate failed instances and restore their limits
                    failed_instances = num_instances - len(ips)
                    db.execute('UPDATE keys SET available_limit = available_limit + ? WHERE user_key = ?', 
                             (failed_instances, user_key))
                    db.commit()
                except Exception as db_error:
                    db.rollback()
                    flash(f"Warning: Could not restore limits for failed instances: {str(db_error)}")
            
            return send_file(file_stream, as_attachment=True, download_name=f"{region}_{instance_type}_instances.txt", mimetype='text/plain')

        flash("No instances were created successfully.")
        if errors:
            for error in errors:
                flash(error)
        return redirect(url_for("index"))
        
    except Exception as e:
        flash(f"An error occurred: {str(e)}")
        return redirect(url_for("index"))

# Delete instances route with error handling
@app.route("/delete_instances", methods=["POST"])
def delete_instances():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No token found for your key.")
        return redirect(url_for("index"))

    token = request.form.get("token")
    instance_ids = request.form.getlist("instance_ids")

    if not instance_ids:
        flash("No instances selected for deletion.")
        return redirect(url_for("index"))

    try:
        # Use ThreadPoolExecutor to delete instances in parallel with a maximum of 5 concurrent deletions
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Create a list to store futures
            futures = []
            
            # Submit deletion tasks
            for instance_id in instance_ids:
                futures.append(executor.submit(delete_linode_instance, instance_id, token))
            
            # Wait for all deletions with a timeout
            timeout_per_instance = 30  # 30 seconds per instance
            total_timeout = timeout_per_instance * len(instance_ids)
            done, not_done = wait(futures, timeout=total_timeout)
            
            if not_done:
                # Cancel any pending tasks
                for future in not_done:
                    future.cancel()
                flash(f"Operation timed out while deleting instances. {len(done)} instances were processed, {len(not_done)} instances were not processed.")
                return redirect(url_for("index"))
            
            # Check for any errors in completed tasks
            success_count = 0
            for future in done:
                try:
                    result = future.result()
                    success_count += 1
                except Exception as e:
                    flash(f"Error during deletion: {str(e)}")

            flash(f"Successfully deleted {success_count} out of {len(instance_ids)} instances.")
            
    except Exception as e:
        flash(f"An error occurred during deletion: {str(e)}")
    
    return redirect(url_for("index"))

@app.route("/get_instances")
def get_instances():
    if 'user_key' not in session:
        return jsonify([])

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        return jsonify([])

    token = request.args.get("token")
    instances = list_linode_instances(token)
    return jsonify(instances)

if __name__ == "__main__":
    app.run(debug=True)