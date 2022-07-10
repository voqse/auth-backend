let users = []
let tokens = []

export async function saveUser(user) {
  users.push(user)
}

export async function getUser(email) {
  return users.find((user) => user.email === email)
}

export async function saveToken(email, token) {
  tokens.push({ email, token })
}

export async function getToken(token) {
  return tokens.find((t) => t.token === token)
}

export async function deleteToken(token) {
  tokens = tokens.filter((t) => t.token !== token)
}
