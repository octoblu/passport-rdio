RdioStrategy = require '../lib/passport-rdio/oauth2strategy'

describe 'RdioStrategy', ->
  beforeEach ->
    @sut = new RdioStrategy { clientID: 'ABC123', clientSecret: 'secret'},() =>
  describe 'userProfile', ->

    it 'should instantiate a strategy with Rdio as the name', ->
      expect(@sut.name).to.equal 'rdio'
