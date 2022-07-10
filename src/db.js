let users = []
let tokens = []

export async function addUser(user) {
  users.push(user)
}

export async function getUser(email) {
  return users.find((user) => user.email === email)
}

export async function addToken(email, token) {
  tokens.push({ email, token })
}

export async function getToken(token) {
  return tokens.find((t) => t.token === token)
}

export async function removeToken(token) {
  tokens = tokens.filter((t) => t.token !== token)
}
