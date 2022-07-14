import mongoose from 'mongoose'
import ms from 'ms'

const { Schema } = mongoose
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
    default: () =>
      new Date(Date.now() + ms(process.env.REFESH_TOKEN_TTL || '15d')),
  },
  createdAt: {
    type: Date,
    default: () => Date.now(),
  },
  createdByIp: {
    type: String,
  },
})

tokenSchema.virtual('isExpired').get(function () {
  return Date.now() >= this.expiresAt
})

tokenSchema.virtual('isActive').get(function () {
  return !this.isExpired
})

tokenSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: ms(process.env.REFESH_TOKEN_TTL || '15d') / 1000 },
)

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
