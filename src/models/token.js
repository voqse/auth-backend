import mongoose, { Schema } from 'mongoose'

const tokenSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  token: {
    type: String,
    required: true,
    unique: true,
  },
  expiresAt: {
    type: Date,
    default: () => Date.now() + (process.env.REFRESH_TOKEN_TTL || '14d') * 1000,
  },
  createdAt: {
    type: Date,
    default: () => Date.now(),
  },
  createdByIp: {
    type: String,
    required: true,
  },
})

tokenSchema.virtual('isExpired').get(function () {
  return Date.now() >= this.expiresAt
})

tokenSchema.virtual('isActive').get(function () {
  return !this.isExpired
})

tokenSchema.set('toJSON', {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    delete ret._id
    delete ret.id
    delete ret.userId
  },
})

export default mongoose.model('Token', tokenSchema)
