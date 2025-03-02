import React, { useState } from "react";
import Post from "./Post";
import classes from "../components/PostList.module.css";
import NewPost from "./NewPost";
import Modal from "./Modal";

const PostList = (props) => {
  const [posts, setPosts] = useState([]); 

  function addPostHandler(postData) {
    setPosts((prevPosts) => [...prevPosts, postData]); 
  }

  return (
    <>
      {props.isPosting && (
        <Modal onClose={props.onStopPosting}>
          <NewPost onCancel={props.onStopPosting} onAddPost={addPostHandler} />
        </Modal>
      )}
      <ul className={classes.posts}>
        {posts.map((post, index) => (
          <Post key={index} name={post.body} course={post.author} />
        ))}
      </ul>
    </>
  );
};

export default PostList;
