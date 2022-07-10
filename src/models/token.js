import mongoose, { Schema } from 'mongoose'

const tokenSchema = new Schema({
  token: {
    type: String,
    required: true,
    unique: true,
  },
  createdAt: {
    type: Date,
    default: () => Date.now(),
  },
})

export default mongoose.model('Token', tokenSchema)
