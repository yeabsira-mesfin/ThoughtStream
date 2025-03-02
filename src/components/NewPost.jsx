import { useState } from 'react';
import classes from './NewPost.module.css';

function NewPost(props) {
  const [text, setText] = useState("");
  const [author, setAuthor] = useState("");

  function bodyChangeHandler(event) {
    setText(event.target.value);
  }
  
  function authorChangeHandler(event) {
    setAuthor(event.target.value);
  }

  function submitHandler(event) {
    event.preventDefault();
    const postData = { body: text, author: author };
    props.onAddPost(postData); 
    setText("");
    setAuthor(""); 
    props.onCancel(); 
  }

  return (
    <form className={classes.form} onSubmit={submitHandler}>
      <p>
        <label htmlFor="body">Text</label>
        <textarea id="body" required rows={3} value={text} onChange={bodyChangeHandler} placeholder="Type Something" />
      </p>
      <p>
        <label htmlFor="name">Your name</label>
        <input type="text" id="name"  required value={author} placeholder='Yeabsiuura' onChange={authorChangeHandler} />
      </p>
      <p className={classes.actions}>
        <button type="button" onClick={props.onCancel}>Cancel</button>
        <button type="submit">Submit</button>
      </p>
    </form>
  );
}

export default NewPost;
