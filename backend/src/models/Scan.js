import mongoose from 'mongoose';

const scanSchema = new mongoose.Schema({
  clientId: {
    type: String,
    required: true,
    index: true,
    match: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  },
  inputType: {
    type: String,
    required: true,
    enum: ['Message', 'URL']
  },
  riskScore: {
    type: Number,
    required: true,
    min: 0,
    max: 100
  },
  riskLevel: {
    type: String,
    required: true,
    enum: ['SAFE', 'SUSPICIOUS', 'HIGH RISK']
  },
  threatType: {
    type: String,
    required: true,
    maxlength: 120
  }
}, {
  timestamps: { createdAt: true, updatedAt: false },
  versionKey: false
});

scanSchema.index({ clientId: 1, createdAt: -1 });

export default mongoose.model('Scan', scanSchema);
