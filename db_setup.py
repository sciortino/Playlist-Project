# Configuration Code:

import sys

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

# Class Code:

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Playlist(Base):

    __tablename__ = 'playlist'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        #Returns object data in easily serializeable format
        return {
            'name' : self.name,
            'id' : self.id,
        }

class Track(Base):

    __tablename__ = 'track'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    artist = Column(String(255))
    album = Column(String(255))
    playlist_id = Column(Integer, ForeignKey('playlist.id'))
    playlist = relationship(Playlist)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        #Returns object data in easily serializeable format
        return {
            'id' : self.id,
            'name' : self.name,
            'artist' : self.artist,
            'album' : self.album,
        }
engine = create_engine('sqlite:///playlistModel.db')

Base.metadata.create_all(engine)
