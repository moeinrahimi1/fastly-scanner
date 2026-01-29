module.exports = {
  packagerConfig: {
    asar: true
  },
  makers: [
    {
      name: "@electron-forge/maker-squirrel",
      config: {}
    },
    {
      name: "@electron-forge/maker-zip",
      platforms: ["darwin", "linux"]
    }
  ]
};
