// import { DataTypes } from "sequelize";
// import { db } from "../config/db.js";

// export const User = db.define(
//   "users", // Table name should usually be lowercase
//   {
//     id: {
//       type: DataTypes.UUID,
//       defaultValue: DataTypes.UUIDV4,
//       primaryKey: true,
//     },
//     username: {
//       type: DataTypes.STRING,
//       allowNull: false,
//       unique: true,
//       lowercase: true, // This is a custom setter/getter property, not a built-in Sequelize type option
//     },
//     email: {
//       type: DataTypes.STRING,
//       allowNull: false,
//       unique: true,
//       lowercase: true,
//     },
//     password: {
//       type: DataTypes.STRING,
//       allowNull: false,
//     },
//     isVerified: {
//       type: DataTypes.BOOLEAN,
//       defaultValue: false,
//     },
//     verificationToken: {
//       type: DataTypes.STRING, // Use DataTypes.STRING
//     },
//     verificationTokenExpires: {
//       type: DataTypes.DATE, // Use DataTypes.DATE
//     },
//     passwordResetToken: {
//       type: DataTypes.STRING,
//     },
//     passwordResetExpires: {
//       type: DataTypes.DATE,
//     },
//     refreshTokens: {
//       // Sequelize stores arrays/JSON as TEXT or JSONB in Postgres
//       type: DataTypes.JSONB,
//       defaultValue: [],
//     },
//     loginAttempts: {
//       type: DataTypes.INTEGER, // Use DataTypes.INTEGER
//       defaultValue: 0,
//     },
//     lockUntil: {
//       type: DataTypes.DATE,
//     },
//   },
//   {
//     tableName: "users", // Explicitly set table name if needed
//     // Sequelize automatically adds createdAt and updatedAt fields by default
//   }
// );

import { DataTypes } from "sequelize";
import { db } from "../config/db.js";

export const User = db.define(
  "users",
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      set(value) {
        this.setDataValue("username", value.toLowerCase());
      },
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      set(value) {
        this.setDataValue("email", value.toLowerCase());
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    isVerified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    verificationToken: DataTypes.STRING,
    verificationTokenExpires: DataTypes.DATE,
    passwordResetToken: DataTypes.STRING,
    passwordResetExpires: DataTypes.DATE,
    refreshTokens: {
      type: DataTypes.JSONB,
      defaultValue: [],
    },
    loginAttempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
    },
    lockUntil: DataTypes.DATE,
  },
  {
    tableName: "users",
  }
);
