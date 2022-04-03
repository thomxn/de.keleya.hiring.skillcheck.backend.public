export interface UserSearchClause {
    id?: object
    name?: object
    email?: object
    updated_at?: object
}

export interface UserUpdatePayload {
    name?: string
    email?: string
    credentials?: object
}

export interface JWTPayload {
    id: Number
    email: string
    isAdmin: boolean
}
