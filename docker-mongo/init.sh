#!/bin/bash
set -e

mongo <<EOF
db.createUser({
  user:  '$MONGO_USERNAME',
  pwd: '$MONGO_PASSWORD',
  roles: [{
    role: 'readWrite',
    db: 'ticked'
  }]
})
db.createCollection('users')
db.createCollection('tasks')
db.createCollection('lists')
EOF